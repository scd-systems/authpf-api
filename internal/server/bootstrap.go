package server

import (
	"context"
	"crypto/rand"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/labstack/echo/v5"
	"github.com/rs/zerolog"
	"github.com/scd-systems/authpf-api/internal/api"
	"github.com/scd-systems/authpf-api/internal/auth"
	"github.com/scd-systems/authpf-api/internal/authpf"
	"github.com/scd-systems/authpf-api/internal/exec"
	"github.com/scd-systems/authpf-api/pkg/config"
	"github.com/scd-systems/authpf-api/pkg/extension"
	"golang.org/x/term"
)

// Global flag storage for logger initialization
var globalForeground bool
var globalLogLevel string

type Server struct {
	config     *config.ConfigFile
	db         *authpf.AnchorsDB
	logger     zerolog.Logger
	httpServer *http.Server
	extensions []extension.Extension
	cancel     context.CancelFunc
}

func NewServer() *Server {
	config := config.New()
	db := authpf.New()
	return &Server{config: config, db: db}
}

func (s *Server) Start() {
	// Bootstrap: Flags, Config, Validierung
	if err := s.Bootstrap(); err != nil {
		log.Fatalf("%s", err.Error())
	}
	// Server: Setup and Start
	e := echo.New()

	// Logger middleware before extensions so blocked requests are still logged
	e.Use(s.loggerMiddleware())
	e.Use(s.requestLoggerMiddleware())

	ctx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel

	// Load extensions
	if err := s.loadExtensions(e, ctx); err != nil {
		cancel()
		log.Fatalf("%s", err.Error())
	}
	if err := s.SetupServer(e); err != nil {
		cancel()
		log.Fatalf("%s", err.Error())
	}
	s.StartServerWithGracefulShutdown(e)
}

// bootstrap initializes the application: flags, config, JWT secret, SSL validation, and logger
func (s *Server) Bootstrap() (err error) {
	// Parse command-line flags (includes config loading)
	if err := s.parseFlags(); err != nil {
		return err
	}

	// Initialize logger
	if err := s.initializeLogger(); err != nil {
		return err
	}

	// Validate Config
	if err := s.validateConfig(); err != nil {
		return err
	}

	// Initialize JWT secret
	if err := s.initializeJWTSecret(); err != nil {
		return err
	}

	// Validate SSL files if enabled
	if err := validateSSLFiles(s.config.Server.SSL.Certificate, s.config.Server.SSL.Key); err != nil {
		return err
	}

	// Create Exec
	e, err := exec.New(s.logger, s.config, s.db)
	if err != nil {
		return err
	}

	// Import existing Anchors
	switch s.config.AuthPF.OnStartup {
	case "import":
		if err := e.ImportAuthPF(); err != nil {
			return err
		}
	case "importflush":
		if err := e.ImportAuthPF(); err != nil {
			return err
		}
		if err := e.FlushAllAnchors("API"); err != nil {
			return err
		}
		s.db.Flush()
	}

	if err := s.validatePfTables(e); err != nil {
		return err
	}

	s.logger.Info().Str("version", Version).Str("API_Version", api.API_VERSION).Msg("authpf-api starting")
	return nil
}

// parseFlags handles command-line flag parsing
func (s *Server) parseFlags() error {
	foreground := flag.Bool("foreground", false, "Log to stdout instead of logfile")
	version := flag.Bool("version", false, "Show version and exit")
	genUserPassword := flag.Bool("gen-user-password", false, "Generate a bcrypt password hash (reads password from stdin)")
	listExtensions := flag.Bool("list-extensions", false, "List registered extensions and exit")
	cfgFile := flag.String("configFile", "", "Filepath to the authpf-api.conf file")
	cfgFileShort := flag.String("c", "", "Filepath to the authpf-api.conf file (short form)")
	logLevel := flag.String("v", "", "Log level (debug, info, warn, error, fatal)")
	flag.Parse()

	if *version {
		displayVersionInfo()
		os.Exit(0)
	}

	if *listExtensions {
		for _, ext := range extension.ListRegistered() {
			fmt.Printf("%s (v%s)\n", ext.Name, ext.Version)
		}
		os.Exit(0)
	}

	if *genUserPassword {
		if err := s.generateUserPasswordHash(); err != nil {
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
		configFilePath = config.CONFIG_FILE
	}

	if configFilePath != "" {
		if err := s.config.LoadConfig(configFilePath); err != nil {
			return fmt.Errorf("failed to load config: %w", err)
		}
	}

	// Store flags for logger initialization
	globalForeground = *foreground
	globalLogLevel = *logLevel
	return nil
}

// initializeJWTSecret sets up the JWT secret from config or generates a random one
func (s *Server) initializeJWTSecret() error {
	if s.config.Server.JwtSecret != "" {
		jwtSecret = []byte(s.config.Server.JwtSecret)
		return nil
	}

	// Generate random JWT secret
	randomSecret := make([]byte, 32)
	if _, err := rand.Read(randomSecret); err != nil {
		return fmt.Errorf("failed to generate JWT secret: %w", err)
	}

	jwtSecret = randomSecret
	s.logger.Warn().Msg("⚠️ Generated random JWT secret (not persisted - configure jwtSecret in config file)")
	return nil
}

// initializeLogger sets up the zerolog logger based on configuration
func (s *Server) initializeLogger() error {
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

	logWriter, err := s.getLogWriter()
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

	s.logger = zerolog.New(consoleWriter).
		With().
		Timestamp().
		Logger().
		Level(level)

	return nil
}

// getLogWriter determines where logs should be written
func (s *Server) getLogWriter() (io.Writer, error) {
	if globalForeground || s.config.Server.Logfile == "" {
		return os.Stdout, nil
	}
	f, err := os.OpenFile(s.config.Server.Logfile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0640)
	return f, err
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

// generateUserPasswordHash reads a password from stdin and generates a bcrypt hash
func (s *Server) generateUserPasswordHash() error {
	var password string
	var err error

	if term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Fprint(os.Stderr, "Enter password: ")
		pw, readErr := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprint(os.Stderr, "\n")
		password = string(pw)
		err = readErr
	} else {
		data, readErr := io.ReadAll(os.Stdin)
		password = strings.TrimSpace(string(data))
		err = readErr
	}
	if err != nil {
		return fmt.Errorf("failed to read password: %w", err)
	}
	if password == "" {
		return fmt.Errorf("password cannot be empty")
	}

	hash, err := auth.GeneratePasswordHash(password)
	if err != nil {
		return fmt.Errorf("failed to generate password hash: %w", err)
	}
	fmt.Println(hash)
	return nil
}

// get all pfTables in config file and put into an array
func gatherPfTablesFromConfig(cfg *config.ConfigFile) []string {
	var tables []string
	seen := make(map[string]bool)

	add := func(t string) {
		if t != "" && !seen[t] {
			seen[t] = true
			tables = append(tables, t)
		}
	}

	add(cfg.AuthPF.PfTable)
	for _, user := range cfg.Rbac.Users {
		add(user.PfTable)
	}

	return tables
}

// loadExtensions loads and initializes extensions from config.
func (s *Server) loadExtensions(framework *echo.Echo, ctx context.Context) error {
	extCtx := extension.Context{
		Context:   ctx,
		Config:    s.config,
		DB:        s.db,
		Logger:    s.logger,
		Framework: framework,
	}
	for _, extCfg := range s.config.Extensions {
		ext, ok := extension.Create(extCfg.Name)
		if !ok {
			return fmt.Errorf("extension %q not found", extCfg.Name)
		}
		if ext.InterfaceVersion() != extension.RequiredInterfaceVersion {
			s.logger.Warn().
				Str("extension", extCfg.Name).
				Int("required", ext.InterfaceVersion()).
				Int("supported", extension.RequiredInterfaceVersion).
				Msg("skipping extension: interface version mismatch")
			continue
		}
		if err := ext.Init(extCtx, extCfg.Config); err != nil {
			return fmt.Errorf("extension %q init failed: %w", extCfg.Name, err)
		}
		s.extensions = append(s.extensions, ext)
		s.logger.Info().Str("extension", extCfg.Name).Msg("extension loaded")
	}
	return nil
}

// Check if all pfTables are exists
func (s *Server) validatePfTables(e *exec.Exec) error {
	tables := gatherPfTablesFromConfig(s.config)
	if len(tables) == 0 {
		return nil
	}

	for _, table := range tables {
		s.logger.Debug().Msgf("checking pf table existence: %s", table)
		if err := e.CheckPfTableExists(table); err != nil {
			return fmt.Errorf("startup pf table check failed: %w", err)
		}
		s.logger.Info().Msgf("pf table verified: %s", table)
	}
	return nil
}
