package main

import (
	"fmt"
	"net/http"
	"os"
	"strings"

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

	// Set Echo's logger level
	e.Logger.SetLevel(getEchoLogLevel())

	// Add HSTS Headers
	e.Use(hstsMiddleWare())

	// Register routes
	registerRoutes(e)

	return nil
}

func checkSSL() {
	if config.Server.SSL.Certificate == "" {
		logger.Warn().Msg("⚠️ WARNING: Running without HTTPS. This is INSECURE!")
	}
}

// Set HSTS-Header
func hstsMiddleWare() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			c.Response().Header().Set("Strict-Transport-Security",
				"max-age=31536000; includeSubDomains; preload")
			c.Response().Header().Set("X-Content-Type-Options", "nosniff")
			c.Response().Header().Set("X-Frame-Options", "DENY")
			c.Response().Header().Set("X-XSS-Protection", "1; mode=block")
			return next(c)
		}
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
			logEntry := logger.Info().
				Str("IP", c.RealIP()).
				Str("Method", c.Request().Method).
				Str("URI", v.URI).
				Int("status", v.Status)
			if username != "" {
				logEntry.Str("user", username)
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

// startServer starts the Echo server with or without TLS
func startServer(e *echo.Echo) error {
	addr := fmt.Sprintf("%s:%d", config.Server.Bind, config.Server.Port)

	if config.Server.SSL.Certificate != "" {
		return e.StartTLS(addr, config.Server.SSL.Certificate, config.Server.SSL.Key)
	}

	return e.Start(addr)
}

// getEchoLogLevel converts LOG_LEVEL environment variable to Echo log level
func getEchoLogLevel() log.Lvl {
	levelStr := os.Getenv("LOG_LEVEL")
	switch strings.ToLower(levelStr) {
	case "debug":
		return log.DEBUG
	case "info":
		return log.INFO
	case "warn":
		return log.WARN
	case "error":
		return log.ERROR
	default:
		return log.INFO
	}
}
