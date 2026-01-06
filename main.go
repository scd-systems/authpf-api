package main

import (
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/labstack/gommon/log"
	"github.com/rs/zerolog"
)

func setLevel() log.Lvl {
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

func main() {
	e := echo.New()
	// Suppress Echo's startup banner and default logger output
	e.HideBanner = true
	// e.Logger.SetOutput(io.Discard) // discard startup logs

	configFile := os.Getenv("CONFIG_FILE")
	if configFile == "" {
		configFile = CONFIG_FILE
	}

	if err := config.loadConfig(configFile); err != nil {
		log.Errorf("%s", err.Error())
		os.Exit(1)
	}

	logLevel := os.Getenv("LOG_LEVEL")
	if logLevel == "" {
		logLevel = "info"
	}
	level, _ := zerolog.ParseLevel(logLevel)

	logger := zerolog.New(os.Stdout).
		With().
		Timestamp().
		Logger().
		Level(level)

	e.Use(middleware.RequestLoggerWithConfig(middleware.RequestLoggerConfig{
		LogURI:       true,
		LogStatus:    true,
		LogUserAgent: true,
		LogRemoteIP:  true,
		LogLatency:   true,
		LogValuesFunc: func(c echo.Context, v middleware.RequestLoggerValues) error {
			logger.Info().
				Str("IP", c.RealIP()).
				Str("Method", c.Request().Method).
				Str("URI", v.URI).
				Int("status", v.Status).
				Msg("request")
			return nil
		},
	}))

	e.Logger.SetLevel(setLevel())

	e.GET("/", func(c echo.Context) error {
		return c.String(http.StatusOK, "Server running")
	})

	// Login endpoint (no authentication required)
	e.POST("/login", login)

	// Register the new POST endpoint for loading authpf rules
	e.POST("/api/v1/authpf/activate", activateAuthPFRule, jwtMiddleware)
	// e.GET("/api/v1/authpf/control/reloadpf", reloadPF, jwtMiddleware)
	e.GET("/api/v1/authpf/activate", getLoadAuthPFRules, jwtMiddleware)
	e.GET("/api/v1/authpf/rules", getLoadAuthPFRules, jwtMiddleware)
	e.DELETE("/api/v1/authpf/activate", deactivateAuthPFRule, jwtMiddleware)
	e.DELETE("/api/v1/authpf/all", deleteAllAuthPFRules, jwtMiddleware)
	go startRuleCleaner(logger)

	if config.Server.SSL.Certificate != "" {
		e.Logger.Fatal(e.StartTLS(fmt.Sprintf("%s:%d", config.Server.Bind, config.Server.Port), config.Server.SSL.Certificate, config.Server.SSL.Key))
	} else {
		e.Logger.Fatal(e.Start(fmt.Sprintf("%s:%d", config.Server.Bind, config.Server.Port)))
	}
}
