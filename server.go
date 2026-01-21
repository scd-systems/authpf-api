package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/labstack/gommon/log"
)

// setupServer configures the Echo server with middleware and routes
func setupServer(e *echo.Echo) error {
	// Suppress Echo's startup banner
	e.HideBanner = true
	checkSSL()

	// Add logger middleware to context
	e.Use(loggerMiddleware())

	// Add request logging middleware
	e.Use(requestLoggerMiddleware())

	// Disable Echo's default logger (we use our own zerolog)
	e.Logger.SetLevel(log.OFF)
	e.Logger.SetOutput(io.Discard)

	// Add HSTS Headers
	e.Use(middleware.SecureWithConfig(middleware.SecureConfig{
		XSSProtection:      "1; mode=block",
		ContentTypeNosniff: "nosniff",
		XFrameOptions:      "DENY",
		HSTSMaxAge:         31536000,
		HSTSPreloadEnabled: true,
	}))

	// Register routes
	registerRoutes(e)

	return nil
}

func checkSSL() {
	if config.Server.SSL.Certificate == "" {
		logger.Warn().Msg("⚠️ WARNING: Running without HTTPS. This is INSECURE!")
	}
}

// loggerMiddleware adds the zerolog logger to the Echo context
func loggerMiddleware() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			c.Set("logger", logger)
			return next(c)
		}
	}
}

// requestLoggerMiddleware logs incoming requests with details
func requestLoggerMiddleware() echo.MiddlewareFunc {
	return middleware.RequestLoggerWithConfig(middleware.RequestLoggerConfig{
		LogURI:       true,
		LogStatus:    true,
		LogUserAgent: true,
		LogRemoteIP:  true,
		LogLatency:   true,
		LogValuesFunc: func(c echo.Context, v middleware.RequestLoggerValues) error {
			username, _ := c.Get("username").(string)
			authStatus, _ := c.Get("auth").(string)
			authpfStatus, _ := c.Get("authpf").(string)
			logEntry := logger.Info().
				Str("IP", c.RealIP()).
				Str("Method", c.Request().Method).
				Str("URI", v.URI).
				Int("status", v.Status)
			if username != "" {
				logEntry.Str("user", username)
			}
			if authStatus != "" {
				logEntry.Str("auth", authStatus)
			}
			if authpfStatus != "" {
				logEntry.Str("authpf", authpfStatus)
			}
			logEntry.Msg("request")
			return nil
		},
	})
}

// registerRoutes sets up all API endpoints
func registerRoutes(e *echo.Echo) {
	// Health check endpoint
	e.GET("/", func(c echo.Context) error {
		return c.String(http.StatusOK, "Server running")
	})

	// Authentication endpoint (no JWT required)
	e.POST("/login", login)

	// AuthPF API endpoints (JWT required)
	e.GET("/api/v1/authpf/activate", getLoadAuthPFRules, jwtMiddleware)
	e.GET("/api/v1/authpf/all", getAllLoadAuthPFRules, jwtMiddleware)
	e.POST("/api/v1/authpf/activate", activateAuthPFRule, jwtMiddleware)
	e.DELETE("/api/v1/authpf/activate", deactivateAuthPFRule, jwtMiddleware)
	e.DELETE("/api/v1/authpf/all", deactivateAllAuthPFRules, jwtMiddleware)

	// Start background rule cleaner
	go startRuleCleaner(logger)
}

// Start Graceful Server
func startServerWithGracefulShutdown(e *echo.Echo) {
	// Channel for OS signals
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	// Graceful shutdown as Goroutine
	go func() {
		s := <-quit
		msg_debug := fmt.Sprintf("Received signal: %s", s)
		logger.Debug().Msg(msg_debug)
		logger.Info().Msg("Graceful shutdown initiated...")
		if err := gracefulShutdown(e); err != nil {
			logger.Error().Err(err).Msg("Shutdown error")
		}
	}()

	if err := startServer(e); err != nil {
		logger.Error().Err(err).Msg("Server error")
		os.Exit(1)
	}
}

// startServer starts the Echo server with or without TLS
func startServer(e *echo.Echo) error {
	addr := fmt.Sprintf("%s:%d", config.Server.Bind, config.Server.Port)

	protocol := "HTTP"
	if config.Server.SSL.Certificate != "" {
		protocol = "HTTPS"
	}
	logger.Info().
		Str("protocol", protocol).
		Str("address", addr).
		Msg("server started")

	if config.Server.SSL.Certificate != "" {
		return e.StartTLS(addr, config.Server.SSL.Certificate, config.Server.SSL.Key)
	}

	return e.Start(addr)
}
