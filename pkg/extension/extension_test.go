package extension

import (
	"net/http"
	"testing"

	"github.com/labstack/echo/v5"
	"github.com/stretchr/testify/assert"
)

// ---------- dummy extension for tests ----------

type dummyExt struct {
	name        string
	routes      []Route
	overrides   map[string]echo.HandlerFunc
	setupErr    error
	validateErr error
}

func (d *dummyExt) Name() string                                       { return d.name }
func (d *dummyExt) Validate(cfg map[string]any) error                  { return d.validateErr }
func (d *dummyExt) Setup(ctx SetupContext, cfg map[string]any) error   { return d.setupErr }
func (d *dummyExt) Routes() []Route                                    { return d.routes }
func (d *dummyExt) OverrideRoutes() map[string]echo.HandlerFunc        { return d.overrides }

// ---------- Registry tests ----------

func TestRegisterAndGet(t *testing.T) {
	// Use a unique name per test to avoid polluting other tests
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

// ---------- Extension interface tests ----------

func TestExtensionRoutes(t *testing.T) {
	h := func(c *echo.Context) error { return c.String(http.StatusOK, "ext") }
	ext := &dummyExt{
		name: "routes-test",
		routes: []Route{
			{Method: "GET", Path: "/api/v1/ext", Handler: h},
		},
	}

	routes := ext.Routes()
	assert.Len(t, routes, 1)
	assert.Equal(t, "GET", routes[0].Method)
	assert.Equal(t, "/api/v1/ext", routes[0].Path)
}

func TestExtensionOverrideRoutes(t *testing.T) {
	customHandler := func(c *echo.Context) error {
		return c.String(http.StatusOK, "overridden")
	}
	ext := &dummyExt{
		name: "override-test",
		overrides: map[string]echo.HandlerFunc{
			"POST /api/v1/authpf/activate": customHandler,
		},
	}

	overrides := ext.OverrideRoutes()
	assert.Len(t, overrides, 1)
	handler, ok := overrides["POST /api/v1/authpf/activate"]
	assert.True(t, ok)
	assert.NotNil(t, handler)
}

func TestExtensionEmptyOverrides(t *testing.T) {
	ext := &dummyExt{name: "empty-overrides"}
	assert.Nil(t, ext.OverrideRoutes())
}

func TestExtensionSetupError(t *testing.T) {
	ext := &dummyExt{name: "setup-err", setupErr: assert.AnError}
	assert.Equal(t, assert.AnError, ext.Setup(SetupContext{}, nil))
}

func TestExtensionSetupSuccess(t *testing.T) {
	ext := &dummyExt{name: "setup-ok"}
	assert.NoError(t, ext.Setup(SetupContext{}, map[string]any{"key": "value"}))
}

func TestExtensionValidateSuccess(t *testing.T) {
	ext := &dummyExt{name: "validate-ok"}
	assert.NoError(t, ext.Validate(map[string]any{"key": "value"}))
}

func TestExtensionValidateError(t *testing.T) {
	ext := &dummyExt{name: "validate-err", validateErr: assert.AnError}
	assert.Equal(t, assert.AnError, ext.Validate(nil))
}

// ---------- Hook constants tests ----------

func TestHookConstants(t *testing.T) {
	assert.Equal(t, "pre-activate", HookPreActivate)
	assert.Equal(t, "post-activate", HookPostActivate)
	assert.Equal(t, "pre-deactivate", HookPreDeactivate)
	assert.Equal(t, "post-deactivate", HookPostDeactivate)
	assert.Equal(t, "post-login", HookPostLogin)
	assert.Equal(t, "server-start", HookServerStart)
	assert.Equal(t, "server-stop", HookServerStop)
}
