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

// TestHandler_SessionUsername
func TestHandler_SessionUsername(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	logger := zerolog.New(os.Stderr)
	handler := &Handler{
		logger: logger,
	}

	// Test with valid username
	c.Set("username", "testuser")
	username, err := handler.sessionUsername(c)

	if err != nil {
		assert.NoError(t, err)
	}

	assert.Equal(t, "testuser", username)
}

// TestHandler_SessionUsername_Missing
func TestHandler_SessionUsername_Missing(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	logger := zerolog.New(os.Stderr)
	handler := &Handler{
		logger: logger,
	}

	// Test with missing username
	username, err := handler.sessionUsername(c)

	assert.Error(t, err)
	assert.Empty(t, username)
	assert.Equal(t, http.StatusUnauthorized, err.HttpStatusCode)
}

// TestHandler_CheckSessionUsername
func TestHandler_CheckSessionUsername(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	logger := zerolog.New(os.Stderr)
	handler := &Handler{
		logger: logger,
	}

	// Test with valid username
	c.Set("username", "testuser")
	err := handler.CheckSessionUsername(c)

	if err != nil {
		assert.NoError(t, err)
	}
}

// TestHandler_CheckSessionUsername_Invalid
func TestHandler_CheckSessionUsername_Invalid(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	logger := zerolog.New(os.Stderr)
	handler := &Handler{
		logger: logger,
	}

	// Test with missing username
	err := handler.CheckSessionUsername(c)

	assert.Error(t, err)
	assert.Equal(t, http.StatusUnauthorized, err.HttpStatusCode)
}

// TestHandler_CheckAnchorIsActivated_NotActivated
func TestHandler_CheckAnchorIsActivated_NotActivated(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	logger := zerolog.New(os.Stderr)
	db := authpf.New()

	handler := &Handler{
		logger: logger,
		db:     db,
	}

	c.Set("username", "testuser")

	isActivated, _ := handler.CheckAnchorIsActivated(c)

	assert.False(t, isActivated)
}

// TestHandler_CheckAnchorIsActivated_AlreadyActivated
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
		logger: logger,
		db:     db,
	}

	c.Set("username", "testuser")

	isActivated, err := handler.CheckAnchorIsActivated(c)

	assert.True(t, isActivated)
	assert.Error(t, err)
	assert.Equal(t, http.StatusAlreadyReported, err.HttpStatusCode)
}

// TestHandler_ResolveAnchorUsername_SessionUser
func TestHandler_ResolveAnchorUsername_SessionUser(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/?authpf_username=", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	cfg := &config.ConfigFile{
		Rbac: config.ConfigFileRbac{
			Users: map[string]config.ConfigFileRbacUsers{
				"testuser": {UserID: 1000, Role: "user"},
			},
		},
	}

	logger := zerolog.New(os.Stderr)
	handler := &Handler{
		config: cfg,
		logger: logger,
	}

	c.Set("username", "testuser")

	username, err := handler.resolveAnchorUsername(c)

	if err != nil {
		assert.NoError(t, err)
	}
	assert.Equal(t, "testuser", username)
}

// TestHandler_ResolveAnchorUsername_QueryUser
func TestHandler_ResolveAnchorUsername_QueryUser(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/?authpf_username=otheruser", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	cfg := &config.ConfigFile{
		Rbac: config.ConfigFileRbac{
			Users: map[string]config.ConfigFileRbacUsers{
				"testuser":  {UserID: 1000, Role: "user"},
				"otheruser": {UserID: 2000, Role: "user"},
			},
		},
	}

	logger := zerolog.New(os.Stderr)
	handler := &Handler{
		config: cfg,
		logger: logger,
	}

	c.Set("username", "testuser")

	username, err := handler.resolveAnchorUsername(c)
	if err != nil {
		assert.NoError(t, err)
	}
	assert.Equal(t, "otheruser", username)
}

// TestHandler_ResolveAnchorTimeout_Default
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
		config: cfg,
		logger: logger,
	}

	timeout, err := handler.resolveAnchorTimeout(c)
	if err != nil {
		assert.NoError(t, err)
	}
	assert.Equal(t, "2h", timeout)
}

// TestHandler_ResolveAnchorTimeout_QueryParam
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
		config: cfg,
		logger: logger,
	}

	timeout, err := handler.resolveAnchorTimeout(c)
	if err != nil {
		assert.NoError(t, err)
	}
	assert.Equal(t, "1h", timeout)
}

// TestHandler_ConcurrentRequests - Race Condition Test
func TestHandler_ConcurrentRequests(t *testing.T) {
	cfg := &config.ConfigFile{
		Rbac: config.ConfigFileRbac{
			Users: map[string]config.ConfigFileRbacUsers{
				"user1": {UserID: 1000, Role: "user"},
				"user2": {UserID: 2000, Role: "user"},
			},
		},
	}

	logger := zerolog.New(os.Stderr)
	handler := &Handler{
		config: cfg,
		logger: logger,
	}

	results := make(chan string, 2)

	// Request 1
	go func() {
		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.Set("username", "user1")

		username, _ := handler.sessionUsername(c)
		results <- username
	}()

	// Request 2
	go func() {
		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.Set("username", "user2")

		username, _ := handler.sessionUsername(c)
		results <- username
	}()

	result1 := <-results
	result2 := <-results

	assert.True(t, (result1 == "user1" && result2 == "user2") || (result1 == "user2" && result2 == "user1"),
		"Expected user1 and user2, got %s and %s", result1, result2)
}

// TestHandler_ValidateUsername tests the validateUsername method with various scenarios
func TestHandler_ValidateUsername(t *testing.T) {
	tests := []struct {
		name           string
		username       string
		users          map[string]config.ConfigFileRbacUsers
		expectError    bool
		expectedStatus int
		expectedMsg    string
		expectedDetail string
	}{
		// Valid usernames
		{
			name:        "valid simple username",
			username:    "testuser",
			users:       map[string]config.ConfigFileRbacUsers{"testuser": {UserID: 1000, Role: "user"}},
			expectError: false,
		},
		{
			name:        "valid username with underscore",
			username:    "test_user",
			users:       map[string]config.ConfigFileRbacUsers{"test_user": {UserID: 1000, Role: "user"}},
			expectError: false,
		},
		{
			name:        "valid username with hyphen",
			username:    "test-user",
			users:       map[string]config.ConfigFileRbacUsers{"test-user": {UserID: 1000, Role: "user"}},
			expectError: false,
		},
		{
			name:        "valid username with numbers",
			username:    "user123",
			users:       map[string]config.ConfigFileRbacUsers{"user123": {UserID: 1000, Role: "user"}},
			expectError: false,
		},
		{
			name:        "valid username with mixed case",
			username:    "TestUser",
			users:       map[string]config.ConfigFileRbacUsers{"TestUser": {UserID: 1000, Role: "user"}},
			expectError: false,
		},
		{
			name:        "valid username with only underscore",
			username:    "_",
			users:       map[string]config.ConfigFileRbacUsers{"_": {UserID: 1000, Role: "user"}},
			expectError: false,
		},
		{
			name:        "valid username with only hyphen",
			username:    "-",
			users:       map[string]config.ConfigFileRbacUsers{"-": {UserID: 1000, Role: "user"}},
			expectError: false,
		},
		{
			name:        "valid complex username",
			username:    "Test_User-123",
			users:       map[string]config.ConfigFileRbacUsers{"Test_User-123": {UserID: 1000, Role: "user"}},
			expectError: false,
		},
		// Invalid format
		{
			name:           "invalid username with @",
			username:       "test@user",
			users:          map[string]config.ConfigFileRbacUsers{},
			expectError:    true,
			expectedStatus: http.StatusBadRequest,
			expectedMsg:    "invalid username format",
			expectedDetail: "username contains invalid characters",
		},
		{
			name:           "invalid username with dot",
			username:       "test.user",
			users:          map[string]config.ConfigFileRbacUsers{},
			expectError:    true,
			expectedStatus: http.StatusBadRequest,
			expectedMsg:    "invalid username format",
			expectedDetail: "username contains invalid characters",
		},
		{
			name:           "invalid username with space",
			username:       "test user",
			users:          map[string]config.ConfigFileRbacUsers{},
			expectError:    true,
			expectedStatus: http.StatusBadRequest,
			expectedMsg:    "invalid username format",
			expectedDetail: "username contains invalid characters",
		},
		{
			name:           "invalid username with hash",
			username:       "test#user",
			users:          map[string]config.ConfigFileRbacUsers{},
			expectError:    true,
			expectedStatus: http.StatusBadRequest,
			expectedMsg:    "invalid username format",
			expectedDetail: "username contains invalid characters",
		},
		{
			name:           "invalid username with dollar",
			username:       "test$user",
			users:          map[string]config.ConfigFileRbacUsers{},
			expectError:    true,
			expectedStatus: http.StatusBadRequest,
			expectedMsg:    "invalid username format",
			expectedDetail: "username contains invalid characters",
		},
		{
			name:           "invalid username with slash",
			username:       "test/user",
			users:          map[string]config.ConfigFileRbacUsers{},
			expectError:    true,
			expectedStatus: http.StatusBadRequest,
			expectedMsg:    "invalid username format",
			expectedDetail: "username contains invalid characters",
		},
		// Length validation
		{
			name:           "username too long (256 chars)",
			username:       string(make([]byte, 256)),
			users:          map[string]config.ConfigFileRbacUsers{},
			expectError:    true,
			expectedStatus: http.StatusBadRequest,
			expectedMsg:    "invalid username",
			expectedDetail: "username too long",
		},
		// User not found
		{
			name:           "user not found",
			username:       "nonexistentuser",
			users:          map[string]config.ConfigFileRbacUsers{"existinguser": {UserID: 1000, Role: "user"}},
			expectError:    true,
			expectedStatus: http.StatusBadRequest,
			expectedMsg:    "user not found",
			expectedDetail: "requested user does not exist",
		},
		{
			name:           "empty username",
			username:       "",
			users:          map[string]config.ConfigFileRbacUsers{},
			expectError:    true,
			expectedStatus: http.StatusBadRequest,
			expectedMsg:    "invalid username format",
			expectedDetail: "username contains invalid characters",
		},
	}

	logger := zerolog.New(os.Stderr)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.ConfigFile{
				Rbac: config.ConfigFileRbac{
					Users: tt.users,
				},
			}

			handler := &Handler{
				config: cfg,
				logger: logger,
			}

			err := handler.validateUsername(tt.username)

			if tt.expectError {
				assert.Error(t, err)
				assert.Equal(t, tt.expectedStatus, err.HttpStatusCode)
				assert.Equal(t, tt.expectedMsg, err.Message)
				assert.Equal(t, tt.expectedDetail, err.Details)
			} else {
				assert.Nil(t, err)
			}
		})
	}
}
