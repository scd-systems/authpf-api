package main

import (
	"crypto/rand"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/labstack/gommon/log"
	"github.com/rs/zerolog"
)

var logger zerolog.Logger

// bootstrap initializes the application: flags, config, JWT secret, SSL validation, and logger
func bootstrap() error {
	// Parse command-line flags
	if err := parseFlags(); err != nil {
		return err
	}

	// Load configuration
	configFile := os.Getenv("CONFIG_FILE")
	if configFile == "" {
		configFile = CONFIG_FILE
	}

	if err := config.loadConfig(configFile); err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Initialize JWT secret
	if err := initializeJWTSecret(); err != nil {
		return err
	}

	// Validate SSL files if enabled
	if err := validateSSLFiles(config.Server.SSL.Certificate, config.Server.SSL.Key); err != nil {
		return err
	}

	// Initialize logger
	if err := initializeLogger(); err != nil {
		return err
	}

	logger.Info().Str("version", Version).Msg("authpf-api starting")
	return nil
}

// parseFlags handles command-line flag parsing
func parseFlags() error {
	foreground := flag.Bool("foreground", false, "Log to stdout instead of logfile")
	version := flag.Bool("version", false, "Show version and exit")
	flag.Parse()

	if *version {
		fmt.Printf("authpf-api version %s\n", Version)
		os.Exit(0)
	}

	// Store foreground flag for logger initialization
	globalForeground = *foreground
	return nil
}

// initializeJWTSecret sets up the JWT secret from config or generates a random one
func initializeJWTSecret() error {
	if config.Server.JwtSecret != "" {
		jwtSecret = []byte(config.Server.JwtSecret)
		return nil
	}

	// Generate random JWT secret
	randomSecret := make([]byte, 32)
	if _, err := rand.Read(randomSecret); err != nil {
		return fmt.Errorf("failed to generate JWT secret: %w", err)
	}

	jwtSecret = randomSecret
	log.Warnf("Generated random JWT secret (not persisted - configure jwtSecret in config file)")
	return nil
}

// initializeLogger sets up the zerolog logger based on configuration
func initializeLogger() error {
	logLevel := os.Getenv("LOG_LEVEL")
	if logLevel == "" {
		logLevel = "info"
	}

	level, err := zerolog.ParseLevel(logLevel)
	if err != nil {
		return fmt.Errorf("invalid log level: %w", err)
	}

	logWriter, err := getLogWriter()
	if err != nil {
		return err
	}

	logger = zerolog.New(logWriter).
		With().
		Timestamp().
		Logger().
		Level(level)

	return nil
}

// getLogWriter determines where logs should be written
func getLogWriter() (io.Writer, error) {
	if globalForeground {
		return os.Stdout, nil
	}

	if config.Server.Logfile != "" {
		file, err := os.OpenFile(config.Server.Logfile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0640)
		if err != nil {
			log.Errorf("Failed to open logfile: %s", err.Error())
			return os.Stdout, nil
		}
		return file, nil
	}

	return os.Stdout, nil
}

// validateSSLFiles checks if SSL certificate and key files exist and are readable
func validateSSLFiles(certPath, keyPath string) error {
	if certPath == "" {
		return nil
	}

	// Check certificate file
	if _, err := os.Stat(certPath); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("SSL certificate file not found: %s", certPath)
		}
		return fmt.Errorf("cannot access SSL certificate file: %s - %v", certPath, err)
	}

	// Check key file
	if _, err := os.Stat(keyPath); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("SSL key file not found: %s", keyPath)
		}
		return fmt.Errorf("cannot access SSL key file: %s - %v", keyPath, err)
	}

	return nil
}

// Global flag storage for logger initialization
var globalForeground bool
