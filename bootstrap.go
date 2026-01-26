package main

import (
	"crypto/rand"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/rs/zerolog"
	"golang.org/x/term"
)

var logger zerolog.Logger

// bootstrap initializes the application: flags, config, JWT secret, SSL validation, and logger
func bootstrap() error {
	// Parse command-line flags (includes config loading)
	if err := parseFlags(); err != nil {
		return err
	}

	// Initialize logger
	if err := initializeLogger(); err != nil {
		return err
	}

	// Initialize JWT secret
	if err := initializeJWTSecret(); err != nil {
		return err
	}

	// Validate SSL files if enabled
	if err := validateSSLFiles(config.Server.SSL.Certificate, config.Server.SSL.Key); err != nil {
		return err
	}

	// Import existing Anchors
	if config.AuthPF.OnStartup == "import" {
		if err := importAuthPF(); err != nil {
			return err
		}
	}
	if config.AuthPF.OnStartup == "importflush" {
		if err := importAuthPF(); err != nil {
			return err
		}
		if err := execUnloadAllAuthPFAnchors("API"); err != nil {
			return err
		}
	}

	logger.Info().Str("version", Version).Str("API_Version", API_VERSION).Msg("authpf-api starting")
	return nil
}

// parseFlags handles command-line flag parsing
func parseFlags() error {
	foreground := flag.Bool("foreground", false, "Log to stdout instead of logfile")
	version := flag.Bool("version", false, "Show version and exit")
	genUserPassword := flag.Bool("gen-user-password", false, "Generate a bcrypt password hash (reads password from stdin)")
	cfgFile := flag.String("configFile", "", "Filepath to the authpf-api.conf file")
	cfgFileShort := flag.String("c", "", "Filepath to the authpf-api.conf file (short form)")
	logLevel := flag.String("v", "", "Log level (debug, info, warn, error, fatal)")
	flag.Parse()

	if *version {
		fmt.Printf("authpf-api version %s\n", Version)
		os.Exit(0)
	}

	if *genUserPassword {
		if err := generateUserPasswordHash(); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0)
	}

	// Handle config file: -c takes precedence, then -configFile, then CONFIG_FILE env var, then default
	configFilePath := ""
	if *cfgFileShort != "" {
		configFilePath = *cfgFileShort
	} else if *cfgFile != "" {
		configFilePath = *cfgFile
	} else if envCfg := os.Getenv("CONFIG_FILE"); envCfg != "" {
		configFilePath = envCfg
	} else {
		configFilePath = CONFIG_FILE
	}

	if configFilePath != "" {
		if err := config.loadConfig(configFilePath); err != nil {
			return fmt.Errorf("failed to load config: %w", err)
		}
	}

	// Store flags for logger initialization
	globalForeground = *foreground
	globalLogLevel = *logLevel
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
	logger.Warn().Msg("⚠️ Generated random JWT secret (not persisted - configure jwtSecret in config file)")
	return nil
}

// initializeLogger sets up the zerolog logger based on configuration
func initializeLogger() error {
	// Priority: -v flag > LOG_LEVEL env var > default "info"
	logLevel := globalLogLevel
	if logLevel == "" {
		logLevel = os.Getenv("LOG_LEVEL")
	}
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

	consoleWriter := zerolog.ConsoleWriter{
		Out:        logWriter,
		TimeFormat: "2006-01-02 15:04:05",
		FormatLevel: func(i interface{}) string {
			level := strings.ToUpper(fmt.Sprintf("%s", i))
			switch level {
			case "DBG":
				return "DEBUG"
			case "INF":
				return "INFO"
			case "WRN":
				return "WARN"
			case "ERR":
				return "ERROR"
			case "FTL":
				return "FATAL"
			default:
				return level
			}
		},
	}

	logger = zerolog.New(consoleWriter).
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
			return os.Stdout, fmt.Errorf("Failed to open file: %s", err.Error())
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
var globalLogLevel string

// generateUserPasswordHash reads a password from stdin and generates a bcrypt hash
func generateUserPasswordHash() error {
	// Check if stdin is a terminal or piped
	isTerminal := term.IsTerminal(int(os.Stdin.Fd()))

	var password string
	var err error

	if isTerminal {
		// Interactive mode: prompt and read without echo
		fmt.Fprint(os.Stderr, "Enter password: ")
		password, err = readPasswordNoEcho()
		if err != nil {
			return fmt.Errorf("failed to read password: %w", err)
		}
		fmt.Fprint(os.Stderr, "\n")
	} else {
		// Piped mode: read from stdin
		password, err = readPasswordFromStdin()
		if err != nil {
			return fmt.Errorf("failed to read password: %w", err)
		}
	}

	if password == "" {
		return fmt.Errorf("password cannot be empty")
	}

	hash, err := GeneratePasswordHash(password)
	if err != nil {
		return fmt.Errorf("failed to generate password hash: %w", err)
	}

	fmt.Println(hash)
	return nil
}

// readPasswordNoEcho reads a password from terminal without echoing it
func readPasswordNoEcho() (string, error) {
	// Disable terminal echo
	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		return "", err
	}
	defer func() {
		if err := term.Restore(int(os.Stdin.Fd()), oldState); err != nil {
			logger.Error().Msg("Cannot restore terminal")
		}
	}()

	// Read password
	password, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return "", err
	}

	return string(password), nil
}

// readPasswordFromStdin reads a password from stdin (for piped input)
func readPasswordFromStdin() (string, error) {
	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		return "", err
	}
	password := strings.TrimSpace(string(data))
	return password, nil
}
