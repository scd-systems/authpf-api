package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/labstack/echo/v5"
	"github.com/labstack/echo/v5/middleware"
	"github.com/scd-systems/authpf-api/internal/api"
	"github.com/scd-systems/authpf-api/internal/auth"
	"github.com/scd-systems/authpf-api/internal/scheduler"
	"github.com/scd-systems/authpf-api/pkg/extension"
)

// setupServer configures the Echo server with middleware and routes
func (s *Server) SetupServer(e *echo.Echo) error {
	s.checkSSL()

	// Disable Echo's default logger (we use our own zerolog)
	e.Logger = slog.New(slog.DiscardHandler)

	// Render all handler/middleware errors as our JSON error schema
	e.HTTPErrorHandler = s.httpErrorHandler

	// Add HSTS Headers
	e.Use(middleware.SecureWithConfig(middleware.SecureConfig{
		XSSProtection:      "1; mode=block",
		ContentTypeNosniff: "nosniff",
		XFrameOptions:      "DENY",
		HSTSMaxAge:         31536000,
		HSTSPreloadEnabled: true,
	}))

	// Apply global middleware from extensions (registration order)
	for _, ext := range s.extensions {
		if mp, ok := ext.(extension.MiddlewareProvider); ok {
			for _, mw := range mp.Middleware() {
				e.Use(adaptMiddleware(mw))
			}
		}
	}

	// Register routes
	if err := s.registerRoutes(e); err != nil {
		return err
	}

	return nil
}

// adaptMiddleware converts a stdlib func(http.Handler)http.Handler to echo.MiddlewareFunc.
func adaptMiddleware(mw func(http.Handler) http.Handler) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c *echo.Context) error {
			mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				c.SetRequest(r)
				c.SetResponse(w)
				_ = next(c)
			})).ServeHTTP(c.Response(), c.Request())
			return nil
		}
	}
}

func (s *Server) checkSSL() {
	if s.config.Server.SSL.Certificate == "" {
		s.logger.Warn().Msg("⚠️ WARNING: Running without HTTPS. This is INSECURE!")
	}
}

// loggerMiddleware adds the zerolog logger to the Echo context
func (s *Server) loggerMiddleware() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c *echo.Context) error {
			c.Set("logger", s.logger)
			return next(c)
		}
	}
}

// requestLoggerMiddleware logs one entry per request, with the level following the status class.
//
// The status is resolved from the pending error, not only from the response: Echo v5 runs
// HTTPErrorHandler after the middleware chain, so resp.Status is still unset for errors here.
func (s *Server) requestLoggerMiddleware() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c *echo.Context) error {
			err := next(c)
			_, status := echo.ResolveResponseStatus(c.Response(), err)

			logEntry := s.logger.Info()
			switch {
			case status >= http.StatusInternalServerError:
				logEntry = s.logger.Error()
			case status >= http.StatusBadRequest:
				logEntry = s.logger.Warn()
			}
			logEntry = logEntry.
				Str("IP", c.RealIP()).
				Str("Method", c.Request().Method).
				Str("URI", c.Request().URL.Path).
				Int("status", status)
			if username, _ := c.Get("username").(string); username != "" {
				logEntry.Str("user", username)
			}
			if authStatus, _ := c.Get("auth").(string); authStatus != "" {
				logEntry.Str("auth", authStatus)
			}
			if authpfStatus, _ := c.Get("authpf").(string); authpfStatus != "" {
				logEntry.Str("authpf", authpfStatus)
			}
			if err != nil {
				logEntry.Err(err)
			}
			logEntry.Msg("request")
			return err
		}
	}
}

// httpErrorHandler renders any handler or middleware error using the API error schema.
// Only echo.HTTPError.Message is sent to the client; the wrapped error stays in the log.
func (s *Server) httpErrorHandler(c *echo.Context, err error) {
	if resp, uErr := echo.UnwrapResponse(c.Response()); uErr == nil && resp.Committed {
		return
	}

	code := echo.StatusCode(err)
	if code == 0 {
		code = http.StatusInternalServerError
	}
	msg := http.StatusText(code)
	var he *echo.HTTPError
	if errors.As(err, &he) && he.Message != "" {
		msg = he.Message
	}

	var cErr error
	if c.Request().Method == http.MethodHead {
		cErr = c.NoContent(code)
	} else {
		cErr = c.JSON(code, map[string]any{"status": "failed", "message": msg})
	}
	if cErr != nil {
		s.logger.Error().Err(cErr).Msg("failed to send error response to client")
	}
}

// registerRoutes sets up all API endpoints
func (s *Server) registerRoutes(e *echo.Echo) error {
	// Create handlers
	handler, err := api.New(s.db, lock, s.logger, s.config)
	if err != nil {
		s.logger.Error().Err(err).Msgf("failed to create handler")
		return err
	}

	auth := auth.New(s.config, s.logger, jwtSecret)

	// Health check endpoint
	e.GET("/", func(c *echo.Context) error {
		return c.JSON(http.StatusOK, map[string]any{"Status": "running"})
	})

	// Authentication endpoint (no JWT required)
	e.POST(ROUTE_LOGIN, auth.Login)
	e.GET(ROUTE_LOGIN, handler.HandleGetLogin, auth.JwtMiddleware)

	// AuthPF API endpoints (JWT required)
	e.GET(ROUTE_AUTHPF, handler.HandleGetActivate, auth.JwtMiddleware)
	e.GET(ROUTE_AUTHPF_ALL, handler.HandleGetAllActivePFAnchors, auth.JwtMiddleware)
	e.POST(ROUTE_AUTHPF, handler.HandlePostActivate, auth.JwtMiddleware)
	e.DELETE(ROUTE_AUTHPF, handler.HandleDeleteDeactivate, auth.JwtMiddleware)
	e.DELETE(ROUTE_AUTHPF_ALL, handler.HandleDeleteAllDeactivate, auth.JwtMiddleware)

	// Info Endpoint
	e.GET("/info", info)

	// Register extension routes (new endpoints)
	for _, ext := range s.extensions {
		if rp, ok := ext.(extension.RouteProvider); ok {
			for _, route := range rp.Routes() {
				switch route.Method {
				case "GET":
					e.GET(route.Path, adaptHandler(route.Handler))
				case "POST":
					e.POST(route.Path, adaptHandler(route.Handler))
				case "DELETE":
					e.DELETE(route.Path, adaptHandler(route.Handler))
				case "PUT":
					e.PUT(route.Path, adaptHandler(route.Handler))
				case "PATCH":
					e.PATCH(route.Path, adaptHandler(route.Handler))
				}
			}
		}
	}

	scheduler := scheduler.New(s.db, lock, s.logger, s.config)
	// Start background rule cleaner
	go scheduler.Run()
	return nil
}

// adaptHandler converts a stdlib http.HandlerFunc to echo.HandlerFunc.
func adaptHandler(h http.HandlerFunc) echo.HandlerFunc {
	return func(c *echo.Context) error {
		h.ServeHTTP(c.Response(), c.Request())
		return nil
	}
}

// Start Graceful Server
func (s *Server) StartServerWithGracefulShutdown(e *echo.Echo) {
	// Channel for OS signals
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	// Graceful shutdown as Goroutine
	go func() {
		signal := <-quit
		msg_debug := fmt.Sprintf("Received signal: %s", signal)
		s.logger.Debug().Msg(msg_debug)
		s.logger.Info().Msg("Graceful shutdown initiated...")
		if err := s.gracefulShutdown(e); err != nil {
			s.logger.Error().Err(err).Msg("Shutdown error")
		}
	}()

	if err := s.startServer(e); err != nil {
		s.logger.Error().Err(err).Msg("Server error")
		os.Exit(1)
	}
}

// startServer starts the Echo server with or without TLS
func (s *Server) startServer(e *echo.Echo) error {
	addr := fmt.Sprintf("%s:%d", s.config.Server.Bind, s.config.Server.Port)

	protocol := "HTTP"
	if s.config.Server.SSL.Certificate != "" {
		protocol = "HTTPS"
	}
	s.logger.Info().
		Str("protocol", protocol).
		Str("address", addr).
		Msg("server started")

	sc := echo.StartConfig{
		Address:    addr,
		HideBanner: true,
		BeforeServeFunc: func(srv *http.Server) error {
			s.httpServer = srv
			return nil
		},
	}

	if s.config.Server.SSL.Certificate != "" {
		return sc.StartTLS(context.Background(), e, s.config.Server.SSL.Certificate, s.config.Server.SSL.Key)
	}

	return sc.Start(context.Background(), e)
}
