package extension

import (
	"context"
	"net/http"

	"github.com/rs/zerolog"
	"github.com/scd-systems/authpf-api/pkg/authpf"
	"github.com/scd-systems/authpf-api/pkg/config"
)

// RequiredInterfaceVersion is the interface version the core supports.
// Extensions must return this value from InterfaceVersion() or be rejected.
const RequiredInterfaceVersion = 1

// Context is passed to Extension.Init() and gives the extension
// access to server-level resources.
type Context struct {
	// Extensions with  background goroutines should select on ctx.Done() to stop cleanly.
	context.Context
	// Config is the server's config file. Extensions may modify it
	// (e.g., to inject RBAC data from an external source).
	Config *config.ConfigFile
	// DB is a read-only view of the in-memory AnchorsDB.
	DB authpf.ReadOnlyAnchorsDB
	// Logger for extension-level logging.
	Logger zerolog.Logger
	// Extensions can type-assert to use framework-specific features
	// like middleware.RateLimiter. nil if no framework is available.
	Framework any
}

// Extension is the minimal interface all extensions must implement.
type Extension interface {
	// Name returns the unique extension identifier
	Name() string

	// Version returns the extension version string (e.g., "1.2.0")
	Version() string

	// InterfaceVersion returns the version of the Extension interface
	// this extension implements. Must match RequiredInterfaceVersion.
	InterfaceVersion() int

	// Init is called once at bootstrap. Extensions should validate their
	// config and perform setup here. Return error to prevent loading.
	// Use ctx.Done() to detect shutdown and stop background goroutines.
	Init(ctx Context, cfg map[string]any) error
}

// Route defines an additional HTTP route provided by an extension.
// Handler uses stdlib http.HandlerFunc so the route survives framework swaps.
type Route struct {
	Method  string
	Path    string
	Handler http.HandlerFunc
}

// RouteProvider is an optional interface. Extensions that want to
// register HTTP routes should implement it.
type RouteProvider interface {
	Routes() []Route
}

// MiddlewareProvider is an optional interface. Extensions that want
// to inject global middleware should implement it.
// Middleware uses stdlib func(http.Handler)http.Handler so it survives
// framework swaps.
type MiddlewareProvider interface {
	Middleware() []func(http.Handler) http.Handler
}
