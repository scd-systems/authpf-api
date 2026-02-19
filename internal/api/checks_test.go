package api

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/rs/zerolog"
	"github.com/scd-systems/authpf-api/internal/authpf"
	"github.com/scd-systems/authpf-api/pkg/config"
	"github.com/stretchr/testify/assert"
)

// TestResolvePermission_ActivateOwnRule tests permission resolution for own rule activation
func TestResolvePermission_ActivateOwnRule(t *testing.T) {
	permission, err := resolvePermission("user1", "user1", config.SESSION_REGISTER)

	assert.NoError(t, err)
	assert.Equal(t, config.RBAC_ACTIVATE_OWN_RULE, permission)
}

// TestResolvePermission_ActivateOtherRule tests permission resolution for other rule activation
func TestResolvePermission_ActivateOtherRule(t *testing.T) {
	permission, err := resolvePermission("admin", "user1", config.SESSION_REGISTER)

	assert.NoError(t, err)
	assert.Equal(t, config.RBAC_ACTIVATE_OTHER_RULE, permission)
}

// TestResolvePermission_DeactivateOwnRule tests permission resolution for own rule deactivation
func TestResolvePermission_DeactivateOwnRule(t *testing.T) {
	permission, err := resolvePermission("user1", "user1", config.SESSION_UNREGISTER)

	assert.NoError(t, err)
	assert.Equal(t, config.RBAC_DEACTIVATE_OWN_RULE, permission)
}

// TestResolvePermission_DeactivateOtherRule tests permission resolution for other rule deactivation
func TestResolvePermission_DeactivateOtherRule(t *testing.T) {
	permission, err := resolvePermission("admin", "user1", config.SESSION_UNREGISTER)

	assert.NoError(t, err)
	assert.Equal(t, config.RBAC_DEACTIVATE_OTHER_RULE, permission)
}

// TestResolvePermission_ViewOwnRule tests permission resolution for own rule viewing
func TestResolvePermission_ViewOwnRule(t *testing.T) {
	permission, err := resolvePermission("user1", "user1", config.SESSION_VIEW)

	assert.NoError(t, err)
	assert.Equal(t, config.RBAC_GET_STATUS_OWN_RULE, permission)
}

// TestResolvePermission_ViewOtherRule tests permission resolution for other rule viewing
func TestResolvePermission_ViewOtherRule(t *testing.T) {
	permission, err := resolvePermission("admin", "user1", config.SESSION_VIEW)

	assert.NoError(t, err)
	assert.Equal(t, config.RBAC_GET_STATUS_OTHER_RULE, permission)
}

// TestResolvePermission_InvalidAction tests permission resolution with invalid action
func TestResolvePermission_InvalidAction(t *testing.T) {
	_, err := resolvePermission("user1", "user1", "invalid_action")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot be used")
}

// TestHandler_GetUserID tests getting user ID from config
func TestHandler_GetUserID(t *testing.T) {
	cfg := &config.ConfigFile{
		Rbac: config.ConfigFileRbac{
			Users: map[string]config.ConfigFileRbacUsers{
				"user1": {UserID: 1000},
				"user2": {UserID: 0},
				"user3": {UserID: 2000},
			},
		},
	}

	logger := zerolog.New(os.Stderr)
	handler := &Handler{
		config: cfg,
		logger: logger,
	}

	tests := []struct {
		name     string
		username string
		expected int
	}{
		{"user with ID", "user1", 1000},
		{"user with zero ID", "user2", 0},
		{"user with ID", "user3", 2000},
		{"non-existent user", "nonexistent", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := handler.getUserID(tt.username)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestHandler_SessionUsername tests session username extraction
func TestHandler_SessionUsername(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	logger := zerolog.New(os.Stderr)
	handler := &Handler{
		ctx:    c,
		logger: logger,
	}

	// Test with valid username
	c.Set("username", "testuser")
	username, err := handler.sessionUsername()

	if err != nil {
		assert.NoError(t, err)
	}

	assert.Equal(t, "testuser", username)
}

// TestHandler_SessionUsername_Missing tests session username extraction with missing username
func TestHandler_SessionUsername_Missing(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	logger := zerolog.New(os.Stderr)
	handler := &Handler{
		ctx:    c,
		logger: logger,
	}

	// Test with missing username
	username, err := handler.sessionUsername()

	assert.Error(t, err)
	assert.Empty(t, username)
	assert.Equal(t, http.StatusUnauthorized, err.HttpStatusCode)
}

// TestHandler_CheckSessionUsername tests session username check
func TestHandler_CheckSessionUsername(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	logger := zerolog.New(os.Stderr)
	handler := &Handler{
		ctx:    c,
		logger: logger,
	}

	// Test with valid username
	c.Set("username", "testuser")
	err := handler.CheckSessionUsername()

	if err != nil {
		assert.NoError(t, err)
	}
}

// TestHandler_CheckSessionUsername_Invalid tests session username check with invalid username
func TestHandler_CheckSessionUsername_Invalid(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	logger := zerolog.New(os.Stderr)
	handler := &Handler{
		ctx:    c,
		logger: logger,
	}

	// Test with missing username
	err := handler.CheckSessionUsername()

	assert.Error(t, err)
	assert.Equal(t, http.StatusUnauthorized, err.HttpStatusCode)
}

// TestHandler_CheckAnchorIsActivated_NotActivated tests anchor activation check when not activated
func TestHandler_CheckAnchorIsActivated_NotActivated(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	logger := zerolog.New(os.Stderr)
	db := authpf.New()

	handler := &Handler{
		ctx:    c,
		logger: logger,
		db:     db,
	}

	c.Set("username", "testuser")

	isActivated, _ := handler.CheckAnchorIsActivated()

	assert.False(t, isActivated)
	// assert.NoError(t, err)
}

// TestHandler_CheckAnchorIsActivated_AlreadyActivated tests anchor activation check when already activated
func TestHandler_CheckAnchorIsActivated_AlreadyActivated(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	logger := zerolog.New(os.Stderr)
	db := authpf.New()

	// Add an anchor to the database
	anchor := &authpf.AuthPFAnchor{
		Username:  "testuser",
		UserID:    1000,
		UserIP:    "192.168.1.1",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}
	db.Add(anchor)

	handler := &Handler{
		ctx:    c,
		logger: logger,
		db:     db,
	}

	c.Set("username", "testuser")

	isActivated, err := handler.CheckAnchorIsActivated()

	assert.True(t, isActivated)
	assert.Error(t, err)
	assert.Equal(t, http.StatusAlreadyReported, err.HttpStatusCode)
}

// TestHandler_ResolveAnchorUsername_SessionUser tests anchor username resolution with session user
func TestHandler_ResolveAnchorUsername_SessionUser(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/?authpf_username=", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	logger := zerolog.New(os.Stderr)
	handler := &Handler{
		ctx:    c,
		logger: logger,
	}

	c.Set("username", "testuser")

	username, err := handler.resolveAnchorUsername()

	if err != nil {
		assert.NoError(t, err)
	}
	assert.Equal(t, "testuser", username)
}

// TestHandler_ResolveAnchorUsername_QueryUser tests anchor username resolution with query parameter
func TestHandler_ResolveAnchorUsername_QueryUser(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/?authpf_username=otheruser", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	logger := zerolog.New(os.Stderr)
	handler := &Handler{
		ctx:    c,
		logger: logger,
	}

	c.Set("username", "testuser")

	username, err := handler.resolveAnchorUsername()
	if err != nil {
		assert.NoError(t, err)
	}
	assert.Equal(t, "otheruser", username)
}

// TestHandler_ResolveAnchorTimeout_Default tests anchor timeout resolution with default
func TestHandler_ResolveAnchorTimeout_Default(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	cfg := &config.ConfigFile{
		AuthPF: config.ConfigFileAuthPF{
			Timeout: "2h",
		},
	}

	logger := zerolog.New(os.Stderr)
	handler := &Handler{
		ctx:    c,
		config: cfg,
		logger: logger,
	}

	timeout, err := handler.resolveAnchorTimeout()
	if err != nil {
		assert.NoError(t, err)
	}
	assert.Equal(t, "2h", timeout)
}

// TestHandler_ResolveAnchorTimeout_QueryParam tests anchor timeout resolution with query parameter
func TestHandler_ResolveAnchorTimeout_QueryParam(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/?timeout=1h", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	cfg := &config.ConfigFile{
		AuthPF: config.ConfigFileAuthPF{
			Timeout: "2h",
		},
	}

	logger := zerolog.New(os.Stderr)
	handler := &Handler{
		ctx:    c,
		config: cfg,
		logger: logger,
	}

	timeout, err := handler.resolveAnchorTimeout()
	if err != nil {
		assert.NoError(t, err)
	}
	assert.Equal(t, "1h", timeout)
}
