package extension

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

// ---------- dummy extension for tests ----------

type dummyExt struct {
	name       string
	routes     []Route
	initErr    error
	middleware []func(http.Handler) http.Handler
}

func (d *dummyExt) Name() string                               { return d.name }
func (d *dummyExt) Version() string                            { return "0.0.0" }
func (d *dummyExt) InterfaceVersion() int                      { return 1 }
func (d *dummyExt) Init(ctx Context, cfg map[string]any) error { return d.initErr }

// Optional interfaces
func (d *dummyExt) Routes() []Route                               { return d.routes }
func (d *dummyExt) Middleware() []func(http.Handler) http.Handler { return d.middleware }

// ---------- Registry tests ----------

func TestRegisterAndGet(t *testing.T) {
	name := "test-reg-" + t.Name()
	Register(name, func() Extension { return &dummyExt{name: name} })

	ext, ok := Get(name)
	assert.True(t, ok)
	assert.Equal(t, name, ext.Name())
}

func TestGetUnknown(t *testing.T) {
	_, ok := Get("nonexistent-extension-" + t.Name())
	assert.False(t, ok)
}

func TestRegisterDuplicatePanics(t *testing.T) {
	name := "test-dup-" + t.Name()
	Register(name, func() Extension { return &dummyExt{name: name} })

	assert.Panics(t, func() {
		Register(name, func() Extension { return &dummyExt{name: name} })
	})
}

// ---------- RouteProvider tests ----------

func TestRouteProvider(t *testing.T) {
	ext := &dummyExt{
		name: "routes-test",
		routes: []Route{
			{Method: "GET", Path: "/api/v1/ext", Handler: func(w http.ResponseWriter, r *http.Request) {}},
		},
	}

	routes := ext.Routes()
	assert.Len(t, routes, 1)
	assert.Equal(t, "GET", routes[0].Method)
	assert.Equal(t, "/api/v1/ext", routes[0].Path)
}

// ---------- MiddlewareProvider tests ----------

func TestMiddlewareProvider(t *testing.T) {
	mw := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, r)
		})
	}

	ext := &dummyExt{name: "mw-test", middleware: []func(http.Handler) http.Handler{mw}}
	mws := ext.Middleware()
	assert.Len(t, mws, 1)
}

// ---------- Init tests ----------

func TestInitError(t *testing.T) {
	ext := &dummyExt{name: "init-err", initErr: assert.AnError}
	assert.Equal(t, assert.AnError, ext.Init(Context{}, nil))
}

func TestInitSuccess(t *testing.T) {
	ext := &dummyExt{name: "init-ok"}
	assert.NoError(t, ext.Init(Context{}, map[string]any{"key": "value"}))
}

// ---------- InterfaceVersion tests ----------

type legacyExt struct {
	dummyExt
}

func (l *legacyExt) InterfaceVersion() int { return 0 }

func TestInterfaceVersion_Mismatch(t *testing.T) {
	ext := &legacyExt{dummyExt: dummyExt{name: "legacy"}}
	assert.Equal(t, 0, ext.InterfaceVersion())
	assert.NotEqual(t, RequiredInterfaceVersion, ext.InterfaceVersion())
}

func TestInterfaceVersion_Match(t *testing.T) {
	ext := &dummyExt{name: "current"}
	assert.Equal(t, RequiredInterfaceVersion, ext.InterfaceVersion())
}
