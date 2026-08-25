package extension

import (
	"github.com/labstack/echo/v5"
	"github.com/rs/zerolog"
	"github.com/scd-systems/authpf-api/internal/authpf"
	"github.com/scd-systems/authpf-api/pkg/config"
)

// SetupContext is passed to Extension.Setup() and gives the extension
// access to server-level resources.
type SetupContext struct {
	// Config is the server's config file. Extensions may modify it
	// (e.g., to inject RBAC data from an external source).
	Config *config.ConfigFile
	// DB is a read-only view of the in-memory AnchorsDB.
	// Extensions cannot call Add, Remove, or Flush.
	DB authpf.ReadOnlyAnchorsDB
	// Logger for extension-level logging.
	Logger zerolog.Logger
}

// Extension is the interface that all extensions must implement.
type Extension interface {
	// Name returns the unique extension identifier, e.g. "billing", "custom-routes".
	Name() string

	// Validate is called before Setup and allows the extension to check
	// its own config (required fields, file existence, etc.).
	// Return error to prevent the extension from loading.
	Validate(cfg map[string]any) error

	// Setup is called once at bootstrap with the extension's config block.
	// Return error to disable the extension.
	Setup(ctx SetupContext, cfg map[string]any) error

	// Routes returns additional HTTP routes to register.
	// Return nil or empty slice if not needed.
	Routes() []Route

	// OverrideRoutes returns handlers that replace core routes.
	// Key is "METHOD /path", e.g. "POST /api/v1/authpf/activate".
	// The core middleware chain (e.g. JwtMiddleware) is preserved.
	// Return nil or empty map if not needed.
	OverrideRoutes() map[string]echo.HandlerFunc

	// Middleware returns echo middleware applied to every route via e.Use().
	// Middleware is applied in extension registration order, before route-specific
	// middleware. Return nil or empty slice if not needed.
	Middleware() []echo.MiddlewareFunc
}

// Route defines an additional HTTP route provided by an extension.
type Route struct {
	Method     string
	Path       string
	Handler    echo.HandlerFunc
	Middleware []echo.MiddlewareFunc
}
