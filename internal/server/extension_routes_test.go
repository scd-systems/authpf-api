package server

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v5"
	"github.com/scd-systems/authpf-api/internal/authpf"
	"github.com/scd-systems/authpf-api/pkg/config"
	"github.com/scd-systems/authpf-api/pkg/extension"
	"github.com/stretchr/testify/assert"
)

// testOverrideExt implements extension.Extension for testing route overrides.
type testOverrideExt struct {
	name      string
	routes    []extension.Route
	overrides map[string]echo.HandlerFunc
}

func (t *testOverrideExt) Name() string                                               { return t.name }
func (t *testOverrideExt) Validate(cfg map[string]any) error                          { return nil }
func (t *testOverrideExt) Setup(ctx extension.SetupContext, cfg map[string]any) error { return nil }
func (t *testOverrideExt) Routes() []extension.Route                                  { return t.routes }
func (t *testOverrideExt) OverrideRoutes() map[string]echo.HandlerFunc                { return t.overrides }
func (t *testOverrideExt) Middleware() []echo.MiddlewareFunc                          { return nil }

func TestRegisterRoutes_OverrideReplacesCore(t *testing.T) {
	// Register a test extension that overrides the POST login route (no middleware)
	overrideHandler := func(c *echo.Context) error {
		return c.String(http.StatusOK, "overridden-login")
	}

	ext := &testOverrideExt{
		name: "test-override-" + t.Name(),
		overrides: map[string]echo.HandlerFunc{
			"POST /login": overrideHandler,
		},
	}

	// Create a test server with the extension
	s := &Server{
		config:     config.New(),
		db:         authpf.New(),
		extensions: []extension.Extension{ext},
	}

	e := echo.New()
	err := s.registerRoutes(e)
	assert.NoError(t, err)

	// Verify the overridden route returns custom response
	req := httptest.NewRequest(http.MethodPost, "/login", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "overridden-login", rec.Body.String())
}

func TestRegisterRoutes_ExtensionRoutesAdded(t *testing.T) {
	customHandler := func(c *echo.Context) error {
		return c.String(http.StatusOK, "custom-endpoint")
	}

	ext := &testOverrideExt{
		name: "test-routes-" + t.Name(),
		routes: []extension.Route{
			{Method: "GET", Path: "/api/v1/custom", Handler: customHandler},
		},
	}

	s := &Server{
		config:     config.New(),
		db:         authpf.New(),
		extensions: []extension.Extension{ext},
	}

	e := echo.New()
	err := s.registerRoutes(e)
	assert.NoError(t, err)

	// Verify the new extension route is registered
	req := httptest.NewRequest(http.MethodGet, "/api/v1/custom", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "custom-endpoint", rec.Body.String())
}

func TestRegisterRoutes_NoExtensionsUsesCore(t *testing.T) {
	s := &Server{
		config:     config.New(),
		db:         authpf.New(),
		extensions: nil,
	}

	e := echo.New()
	err := s.registerRoutes(e)
	assert.NoError(t, err)

	// Health check should still work
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "running")
}

func TestLoadExtensions_FromConfig(t *testing.T) {
	// Register a test extension
	name := "test-load-" + t.Name()
	extension.Register(name, func() extension.Extension {
		return &testOverrideExt{name: name}
	})

	s := &Server{
		config: &config.ConfigFile{
			Extensions: []config.ConfigFileExtension{
				{Name: name, Config: map[string]any{"key": "value"}},
			},
		},
		db: authpf.New(),
	}

	err := s.loadExtensions()
	assert.NoError(t, err)
	assert.Len(t, s.extensions, 1)
	assert.Equal(t, name, s.extensions[0].Name())
}

func TestLoadExtensions_NotFound(t *testing.T) {
	s := &Server{
		config: &config.ConfigFile{
			Extensions: []config.ConfigFileExtension{
				{Name: "nonexistent-ext-" + t.Name()},
			},
		},
		db: authpf.New(),
	}

	err := s.loadExtensions()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestLoadExtensions_SetupError(t *testing.T) {
	name := "test-setup-err-" + t.Name()
	extension.Register(name, func() extension.Extension {
		return &dummyExtWithSetupError{name: name}
	})

	s := &Server{
		config: &config.ConfigFile{
			Extensions: []config.ConfigFileExtension{
				{Name: name},
			},
		},
		db: authpf.New(),
	}

	err := s.loadExtensions()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "setup failed")
}

func TestRegisterRoutes_GlobalMiddlewareApplied(t *testing.T) {
	// Middleware that sets a flag on the context
	mwCalled := false
	mw := func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c *echo.Context) error {
			mwCalled = true
			return next(c)
		}
	}

	ext := &testOverrideExt{
		name: "test-mw-" + t.Name(),
	}
	wrapped := &testOverrideExtWithMW{
		base: ext,
		mw:   []echo.MiddlewareFunc{mw},
	}

	s := &Server{
		config:     config.New(),
		db:         authpf.New(),
		extensions: []extension.Extension{wrapped},
	}

	e := echo.New()
	err := s.SetupServer(e)
	assert.NoError(t, err)

	// Hit the health check endpoint — core route, should still trigger extension middleware
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.True(t, mwCalled, "global middleware should have been called")
}

// testOverrideExtWithMW wraps testOverrideExt and returns custom middleware
type testOverrideExtWithMW struct {
	base *testOverrideExt
	mw   []echo.MiddlewareFunc
}

func (w *testOverrideExtWithMW) Name() string                      { return w.base.Name() }
func (w *testOverrideExtWithMW) Validate(cfg map[string]any) error { return w.base.Validate(cfg) }
func (w *testOverrideExtWithMW) Setup(ctx extension.SetupContext, cfg map[string]any) error {
	return w.base.Setup(ctx, cfg)
}
func (w *testOverrideExtWithMW) Routes() []extension.Route { return w.base.Routes() }
func (w *testOverrideExtWithMW) OverrideRoutes() map[string]echo.HandlerFunc {
	return w.base.OverrideRoutes()
}
func (w *testOverrideExtWithMW) Middleware() []echo.MiddlewareFunc { return w.mw }

func TestLoadExtensions_ValidateError(t *testing.T) {
	name := "test-validate-err-" + t.Name()
	extension.Register(name, func() extension.Extension {
		return &dummyExtWithValidateError{name: name}
	})

	s := &Server{
		config: &config.ConfigFile{
			Extensions: []config.ConfigFileExtension{
				{Name: name},
			},
		},
		db: authpf.New(),
	}

	err := s.loadExtensions()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "validation failed")
}

// dummyExtWithSetupError always returns an error on Setup
type dummyExtWithSetupError struct {
	name string
}

func (d *dummyExtWithSetupError) Name() string                      { return d.name }
func (d *dummyExtWithSetupError) Validate(cfg map[string]any) error { return nil }
func (d *dummyExtWithSetupError) Setup(ctx extension.SetupContext, cfg map[string]any) error {
	return fmt.Errorf("setup failed")
}
func (d *dummyExtWithSetupError) Routes() []extension.Route                   { return nil }
func (d *dummyExtWithSetupError) OverrideRoutes() map[string]echo.HandlerFunc { return nil }
func (d *dummyExtWithSetupError) Middleware() []echo.MiddlewareFunc           { return nil }

// dummyExtWithValidateError always returns an error on Validate
type dummyExtWithValidateError struct {
	name string
}

func (d *dummyExtWithValidateError) Name() string { return d.name }
func (d *dummyExtWithValidateError) Validate(cfg map[string]any) error {
	return fmt.Errorf("validation failed")
}
func (d *dummyExtWithValidateError) Setup(ctx extension.SetupContext, cfg map[string]any) error {
	return nil
}
func (d *dummyExtWithValidateError) Routes() []extension.Route                   { return nil }
func (d *dummyExtWithValidateError) OverrideRoutes() map[string]echo.HandlerFunc { return nil }
func (d *dummyExtWithValidateError) Middleware() []echo.MiddlewareFunc           { return nil }
