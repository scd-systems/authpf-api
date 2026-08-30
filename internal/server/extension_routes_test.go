package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v5"
	"github.com/scd-systems/authpf-api/internal/authpf"
	"github.com/scd-systems/authpf-api/pkg/config"
	"github.com/scd-systems/authpf-api/pkg/extension"
	"github.com/stretchr/testify/assert"
)

// testExt implements extension.Extension + optional interfaces for testing.
type testExt struct {
	name       string
	routes     []extension.Route
	middleware []func(http.Handler) http.Handler
	initErr    error
}

func (t *testExt) Name() string                                         { return t.name }
func (t *testExt) Version() string                                      { return "0.0.0" }
func (t *testExt) InterfaceVersion() int                                { return 1 }
func (t *testExt) Init(ctx extension.Context, cfg map[string]any) error { return t.initErr }
func (t *testExt) Routes() []extension.Route                            { return t.routes }
func (t *testExt) Middleware() []func(http.Handler) http.Handler        { return t.middleware }

func TestRegisterRoutes_ExtensionRoutesAdded(t *testing.T) {
	ext := &testExt{
		name: "test-routes-" + t.Name(),
		routes: []extension.Route{
			{Method: "GET", Path: "/api/v1/custom", Handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("custom-endpoint"))
			}},
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

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "running")
}

func TestLoadExtensions_FromConfig(t *testing.T) {
	name := "test-load-" + t.Name()
	extension.Register(name, func() extension.Extension {
		return &testExt{name: name}
	})

	s := &Server{
		config: &config.ConfigFile{
			Extensions: []config.ConfigFileExtension{
				{Name: name, Config: map[string]any{"key": "value"}},
			},
		},
		db: authpf.New(),
	}

	e := echo.New()
	ctx := context.Background()
	err := s.loadExtensions(e, ctx)
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

	e := echo.New()
	ctx := context.Background()
	err := s.loadExtensions(e, ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestLoadExtensions_InitError(t *testing.T) {
	name := "test-init-err-" + t.Name()
	extension.Register(name, func() extension.Extension {
		return &testExt{name: name, initErr: assert.AnError}
	})

	s := &Server{
		config: &config.ConfigFile{
			Extensions: []config.ConfigFileExtension{
				{Name: name},
			},
		},
		db: authpf.New(),
	}

	e := echo.New()
	ctx := context.Background()
	err := s.loadExtensions(e, ctx)
	assert.Error(t, err)
}

func TestRegisterRoutes_GlobalMiddlewareApplied(t *testing.T) {
	mwCalled := false
	mw := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mwCalled = true
			next.ServeHTTP(w, r)
		})
	}

	ext := &testExt{
		name:       "test-mw-" + t.Name(),
		middleware: []func(http.Handler) http.Handler{mw},
	}

	s := &Server{
		config:     config.New(),
		db:         authpf.New(),
		extensions: []extension.Extension{ext},
	}

	e := echo.New()
	err := s.SetupServer(e)
	assert.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.True(t, mwCalled, "global middleware should have been called")
}
