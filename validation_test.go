package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
)

// TestValidationError_Error tests the Error method of ValidationError
func TestValidationError_Error(t *testing.T) {
	tests := []struct {
		name     string
		ve       *ValidationError
		expected string
	}{
		{
			name: "with details",
			ve: &ValidationError{
				StatusCode: http.StatusBadRequest,
				Message:    "invalid input",
				Details:    "field is required",
			},
			expected: "invalid input: field is required",
		},
		{
			name: "without details",
			ve: &ValidationError{
				StatusCode: http.StatusBadRequest,
				Message:    "invalid input",
				Details:    "",
			},
			expected: "invalid input",
		},
		{
			name: "empty message and details",
			ve: &ValidationError{
				StatusCode: http.StatusBadRequest,
				Message:    "",
				Details:    "",
			},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.ve.Error()
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestValidateSessionUsername_ValidUsername tests successful username extraction
func TestValidateSessionUsername_ValidUsername(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.Set("username", "testuser")

	username, err := ValidateSessionUsername(c)

	assert.Nil(t, err)
	assert.Equal(t, "testuser", username)
}

// TestValidateSessionUsername_MissingUsername tests missing username in context
func TestValidateSessionUsername_MissingUsername(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	username, err := ValidateSessionUsername(c)

	assert.Error(t, err)
	assert.Equal(t, "", username)
	assert.Equal(t, http.StatusUnauthorized, err.StatusCode)
	assert.Equal(t, "invalid username in token", err.Message)
}

// TestValidateSessionUsername_EmptyUsername tests empty username in context
func TestValidateSessionUsername_EmptyUsername(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.Set("username", "")

	username, err := ValidateSessionUsername(c)

	assert.Error(t, err)
	assert.Equal(t, "", username)
	assert.Equal(t, http.StatusUnauthorized, err.StatusCode)
}

// TestValidateSessionUsername_WrongType tests wrong type in context
func TestValidateSessionUsername_WrongType(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.Set("username", 123) // Wrong type

	username, err := ValidateSessionUsername(c)

	assert.Error(t, err)
	assert.Equal(t, "", username)
	assert.Equal(t, http.StatusUnauthorized, err.StatusCode)
}

// TestValidatePayload_ValidJSON tests successful JSON payload binding
func TestValidatePayload_ValidJSON(t *testing.T) {
	e := echo.New()
	rule := &AuthPFRule{
		Username: "testuser",
		UserIP:   "192.168.1.1",
		Timeout:  "1h",
	}
	bodyBytes, _ := json.Marshal(rule)

	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	var result AuthPFRule
	err := ValidatePayload(c, &result)

	assert.Nil(t, err)
	assert.Equal(t, "testuser", result.Username)
	assert.Equal(t, "192.168.1.1", result.UserIP)
}

// TestValidatePayload_InvalidJSON tests invalid JSON payload
func TestValidatePayload_InvalidJSON(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte("invalid json")))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	var result AuthPFRule
	err := ValidatePayload(c, &result)

	assert.Error(t, err)
	assert.Equal(t, http.StatusBadRequest, err.StatusCode)
	assert.Equal(t, "invalid JSON payload", err.Message)
}

// TestValidatePayload_EmptyBody tests empty request body
func TestValidatePayload_EmptyBody(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte("{}")))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	var result AuthPFRule
	err := ValidatePayload(c, &result)

	assert.Nil(t, err)
}

// TestValidateTimeout_ValidTimeout tests valid timeout parsing
func TestValidateTimeout_ValidTimeout(t *testing.T) {
	tests := []struct {
		name    string
		timeout string
		minDiff time.Duration
		maxDiff time.Duration
	}{
		{
			name:    "1 minute",
			timeout: "1m",
			minDiff: 0,
			maxDiff: 1 * time.Second,
		},
		{
			name:    "1 hour",
			timeout: "1h",
			minDiff: 0,
			maxDiff: 1 * time.Second,
		},
		{
			name:    "24 hours",
			timeout: "24h",
			minDiff: 0,
			maxDiff: 1 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			before := time.Now()
			timeoutStr, expiresAt, err := ValidateTimeout(tt.timeout)

			assert.Nil(t, err)
			assert.Equal(t, tt.timeout, timeoutStr)
			assert.False(t, expiresAt.IsZero())

			// Verify expiration time is approximately correct
			duration, _ := time.ParseDuration(tt.timeout)
			expectedExpiration := before.Add(duration)
			diff := expiresAt.Sub(expectedExpiration).Abs()
			assert.Less(t, diff, 100*time.Millisecond)
		})
	}
}

// TestValidateTimeout_EmptyTimeout tests empty timeout with default
func TestValidateTimeout_EmptyTimeout(t *testing.T) {
	config.Defaults.Timeout = "30m"

	timeoutStr, expiresAt, err := ValidateTimeout("")

	assert.Nil(t, err)
	assert.Equal(t, "30m", timeoutStr)
	assert.False(t, expiresAt.IsZero())
}

// TestValidateTimeout_EmptyTimeoutNoDefault tests empty timeout without default
func TestValidateTimeout_EmptyTimeoutNoDefault(t *testing.T) {
	config.Defaults.Timeout = ""

	timeoutStr, expiresAt, err := ValidateTimeout("")

	assert.Nil(t, err)
	assert.Equal(t, "", timeoutStr)
	assert.True(t, expiresAt.IsZero())
}

// TestValidateTimeout_InvalidFormat tests invalid timeout format
func TestValidateTimeout_InvalidFormat(t *testing.T) {
	config.Defaults.Timeout = ""

	_, _, err := ValidateTimeout("invalid")

	assert.Error(t, err)
	assert.Equal(t, http.StatusBadRequest, err.StatusCode)
	assert.Equal(t, "invalid timeout format", err.Message)
}

// TestValidateTimeout_TooShort tests timeout less than 1 minute
func TestValidateTimeout_TooShort(t *testing.T) {
	config.Defaults.Timeout = ""

	_, _, err := ValidateTimeout("30s")

	assert.Error(t, err)
	assert.Equal(t, http.StatusBadRequest, err.StatusCode)
	assert.Equal(t, "timeout must be at least 1 minute", err.Message)
}

// TestValidateTimeout_TooLong tests timeout exceeding 24 hours
func TestValidateTimeout_TooLong(t *testing.T) {
	config.Defaults.Timeout = ""

	_, _, err := ValidateTimeout("25h")

	assert.Error(t, err)
	assert.Equal(t, http.StatusBadRequest, err.StatusCode)
	assert.Equal(t, "timeout cannot exceed 24 hours", err.Message)
}

// TestValidateUsername_ValidUsername tests valid username validation
func TestValidateUsername_ValidUsername(t *testing.T) {
	config.Rbac.Users = map[string]ConfigFileRbacUsers{
		"testuser": {
			Password: "hashedpassword",
			Role:     "user",
		},
	}

	err := ValidateUsername("testuser")

	assert.Nil(t, err)
}

// TestValidateUsername_InvalidUsername tests invalid username validation
func TestValidateUsername_InvalidUsername(t *testing.T) {
	config.Rbac.Users = map[string]ConfigFileRbacUsers{
		"testuser": {
			Password: "hashedpassword",
			Role:     "user",
		},
	}

	err := ValidateUsername("nonexistent")

	assert.Error(t, err)
	assert.Equal(t, http.StatusBadRequest, err.StatusCode)
	assert.Equal(t, "invalid username", err.Message)
}

// TestCheckPermission_ValidPermission tests valid permission check
func TestCheckPermission_ValidPermission(t *testing.T) {
	config.Rbac.Users = map[string]ConfigFileRbacUsers{
		"testuser": {
			Password: "hashedpassword",
			Role:     "admin",
		},
	}
	config.Rbac.Roles = map[string]ConfigFileRbacRoles{
		"admin": {
			Permissions: []string{"activate_own_rules", "activate_other_rules"},
		},
	}

	logger := zerolog.New(nil)
	err := CheckPermission("testuser", "activate_own_rules", logger)

	assert.Nil(t, err)
}

// TestCheckPermission_InvalidPermission tests invalid permission check
func TestCheckPermission_InvalidPermission(t *testing.T) {
	config.Rbac.Users = map[string]ConfigFileRbacUsers{
		"testuser": {
			Password: "hashedpassword",
			Role:     "user",
		},
	}
	config.Rbac.Roles = map[string]ConfigFileRbacRoles{
		"user": {
			Permissions: []string{"view_own_rules"},
		},
	}

	logger := zerolog.New(nil)
	err := CheckPermission("testuser", "activate_own_rules", logger)

	assert.Error(t, err)
	assert.Equal(t, http.StatusForbidden, err.StatusCode)
	assert.Equal(t, "permission denied", err.Message)
}

// TestResolveTargetUser_SameUser tests resolving target user when same as session user
func TestResolveTargetUser_SameUser(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	config.Rbac.Users = map[string]ConfigFileRbacUsers{
		"testuser": {
			Password: "hashedpassword",
			Role:     "user",
		},
	}

	logger := zerolog.New(nil)
	targetUser, err := ResolveTargetUser(c, "testuser", "testuser", "activate_own_rules", logger)

	assert.Nil(t, err)
	assert.Equal(t, "testuser", targetUser)
}

// TestResolveTargetUser_EmptyRequestedUser tests resolving target user with empty requested user
func TestResolveTargetUser_EmptyRequestedUser(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	config.Rbac.Users = map[string]ConfigFileRbacUsers{
		"testuser": {
			Password: "hashedpassword",
			Role:     "user",
		},
	}

	logger := zerolog.New(nil)
	targetUser, err := ResolveTargetUser(c, "testuser", "", "activate_own_rules", logger)

	assert.Nil(t, err)
	assert.Equal(t, "testuser", targetUser)
}

// TestResolveTargetUser_DifferentUserWithPermission tests resolving different user with permission
func TestResolveTargetUser_DifferentUserWithPermission(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	config.Rbac.Users = map[string]ConfigFileRbacUsers{
		"admin": {
			Password: "hashedpassword",
			Role:     "admin",
		},
		"testuser": {
			Password: "hashedpassword",
			Role:     "user",
		},
	}
	config.Rbac.Roles = map[string]ConfigFileRbacRoles{
		"admin": {
			Permissions: []string{"activate_other_rules"},
		},
	}

	logger := zerolog.New(nil)
	targetUser, err := ResolveTargetUser(c, "admin", "testuser", "activate_other_rules", logger)

	assert.Nil(t, err)
	assert.Equal(t, "testuser", targetUser)
}

// TestResolveTargetUser_DifferentUserInvalidUsername tests resolving different user with invalid username
func TestResolveTargetUser_DifferentUserInvalidUsername(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	config.Rbac.Users = map[string]ConfigFileRbacUsers{
		"admin": {
			Password: "hashedpassword",
			Role:     "admin",
		},
	}

	logger := zerolog.New(nil)
	targetUser, err := ResolveTargetUser(c, "admin", "nonexistent", "activate_other_rules", logger)

	assert.Error(t, err)
	assert.Equal(t, "", targetUser)
	assert.Equal(t, http.StatusBadRequest, err.StatusCode)
}

// TestResolveTargetUser_DifferentUserNoPermission tests resolving different user without permission
func TestResolveTargetUser_DifferentUserNoPermission(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	config.Rbac.Users = map[string]ConfigFileRbacUsers{
		"user1": {
			Password: "hashedpassword",
			Role:     "user",
		},
		"user2": {
			Password: "hashedpassword",
			Role:     "user",
		},
	}
	config.Rbac.Roles = map[string]ConfigFileRbacRoles{
		"user": {
			Permissions: []string{"activate_own_rules"},
		},
	}

	logger := zerolog.New(nil)
	targetUser, err := ResolveTargetUser(c, "user1", "user2", "activate_other_rules", logger)

	assert.Error(t, err)
	assert.Equal(t, "", targetUser)
	assert.Equal(t, http.StatusForbidden, err.StatusCode)
}

// TestCheckSessionExists_ActivateWithExistingSession tests activate mode with existing session
func TestCheckSessionExists_ActivateWithExistingSession(t *testing.T) {
	rulesdb["testuser"] = &AuthPFRule{
		Username: "testuser",
		UserIP:   "192.168.1.1",
	}
	defer delete(rulesdb, "testuser")

	logger := zerolog.New(nil)
	err := CheckSessionExists("testuser", logger, "activate")

	assert.Error(t, err)
	assert.Equal(t, http.StatusMethodNotAllowed, err.StatusCode)
	assert.Equal(t, "authpf rule for user already activated", err.Message)
}

// TestCheckSessionExists_ActivateWithoutExistingSession tests activate mode without existing session
func TestCheckSessionExists_ActivateWithoutExistingSession(t *testing.T) {
	delete(rulesdb, "testuser")

	logger := zerolog.New(nil)
	err := CheckSessionExists("testuser", logger, "activate")

	assert.Nil(t, err)
}

// TestCheckSessionExists_DeactivateWithExistingSession tests deactivate mode with existing session
func TestCheckSessionExists_DeactivateWithExistingSession(t *testing.T) {
	rulesdb["testuser"] = &AuthPFRule{
		Username: "testuser",
		UserIP:   "192.168.1.1",
	}
	defer delete(rulesdb, "testuser")

	logger := zerolog.New(nil)
	err := CheckSessionExists("testuser", logger, "deactivate")

	assert.Nil(t, err)
}

// TestCheckSessionExists_DeactivateWithoutExistingSession tests deactivate mode without existing session
func TestCheckSessionExists_DeactivateWithoutExistingSession(t *testing.T) {
	delete(rulesdb, "testuser")

	logger := zerolog.New(nil)
	err := CheckSessionExists("testuser", logger, "deactivate")

	assert.Error(t, err)
	assert.Equal(t, http.StatusMethodNotAllowed, err.StatusCode)
	assert.Equal(t, "authpf rule for user not activated", err.Message)
}

// TestCheckSessionExists_InvalidMode tests invalid mode
func TestCheckSessionExists_InvalidMode(t *testing.T) {
	logger := zerolog.New(nil)
	err := CheckSessionExists("testuser", logger, "invalid")

	assert.Error(t, err)
	assert.Equal(t, http.StatusInternalServerError, err.StatusCode)
	assert.Equal(t, "internal server error", err.Message)
}

// TestSetUserID_WithUserID tests setting UserID from config
func TestSetUserID_WithUserID(t *testing.T) {
	config.Rbac.Users = map[string]ConfigFileRbacUsers{
		"testuser": {
			Password: "hashedpassword",
			Role:     "user",
			UserID:   1001,
		},
	}

	rule := &AuthPFRule{
		Username: "testuser",
		UserIP:   "192.168.1.1",
	}

	SetUserID(rule)

	assert.Equal(t, 1001, rule.UserID)
}

// TestSetUserID_WithoutUserID tests SetUserID when UserID is not set in config
func TestSetUserID_WithoutUserID(t *testing.T) {
	config.Rbac.Users = map[string]ConfigFileRbacUsers{
		"testuser": {
			Password: "hashedpassword",
			Role:     "user",
			UserID:   0,
		},
	}

	rule := &AuthPFRule{
		Username: "testuser",
		UserIP:   "192.168.1.1",
		UserID:   0,
	}

	SetUserID(rule)

	assert.Equal(t, 0, rule.UserID)
}

// TestSetUserID_UserNotInConfig tests SetUserID when user is not in config
func TestSetUserID_UserNotInConfig(t *testing.T) {
	config.Rbac.Users = map[string]ConfigFileRbacUsers{}

	rule := &AuthPFRule{
		Username: "testuser",
		UserIP:   "192.168.1.1",
		UserID:   0,
	}

	SetUserID(rule)

	assert.Equal(t, 0, rule.UserID)
}

// TestRespondWithValidationError_WithError tests responding with validation error
func TestRespondWithValidationError_WithError(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	valErr := &ValidationError{
		StatusCode: http.StatusBadRequest,
		Message:    "invalid input",
		Details:    "field is required",
	}

	err := RespondWithValidationError(c, valErr)

	assert.Nil(t, err)
	assert.Equal(t, http.StatusBadRequest, rec.Code)

	var response map[string]string
	json.Unmarshal(rec.Body.Bytes(), &response)
	assert.Equal(t, "invalid input", response["error"])
	assert.Equal(t, "field is required", response["details"])
}

// TestRespondWithValidationError_WithNilError tests responding with nil error
func TestRespondWithValidationError_WithNilError(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err := RespondWithValidationError(c, nil)

	assert.Nil(t, err)
}

// TestRespondWithValidationErrorStatus_WithError tests responding with validation error status
func TestRespondWithValidationErrorStatus_WithError(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	valErr := &ValidationError{
		StatusCode: http.StatusForbidden,
		Message:    "permission denied",
		Details:    "user lacks required permission",
	}

	err := RespondWithValidationErrorStatus(c, valErr)

	assert.Nil(t, err)
	assert.Equal(t, http.StatusForbidden, rec.Code)

	var response map[string]string
	json.Unmarshal(rec.Body.Bytes(), &response)
	assert.Equal(t, "rejected", response["status"])
	assert.Equal(t, "permission denied", response["message"])
	assert.Equal(t, "user lacks required permission", response["details"])
}

// TestRespondWithValidationErrorStatus_WithNilError tests responding with nil error status
func TestRespondWithValidationErrorStatus_WithNilError(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err := RespondWithValidationErrorStatus(c, nil)

	assert.Nil(t, err)
}

// TestValidateUserIP_ValidIPv4 tests valid IPv4 address validation
func TestValidateUserIP_ValidIPv4(t *testing.T) {
	tests := []string{
		"192.168.1.1",
		"10.0.0.1",
		"172.16.0.1",
		"127.0.0.1",
		"255.255.255.255",
		"0.0.0.0",
	}

	for _, ip := range tests {
		t.Run(ip, func(t *testing.T) {
			err := ValidateUserIP(ip)
			assert.Nil(t, err)
		})
	}
}

// TestValidateUserIP_ValidIPv6 tests valid IPv6 address validation
func TestValidateUserIP_ValidIPv6(t *testing.T) {
	tests := []string{
		"::1",
		"2001:db8::1",
		"fe80::1",
		"::ffff:192.0.2.1",
		"2001:0db8:85a3:0000:0000:8a2e:0370:7334",
	}

	for _, ip := range tests {
		t.Run(ip, func(t *testing.T) {
			err := ValidateUserIP(ip)
			assert.Nil(t, err)
		})
	}
}

// TestValidateUserIP_EmptyIP tests empty IP address validation
func TestValidateUserIP_EmptyIP(t *testing.T) {
	err := ValidateUserIP("")

	assert.Error(t, err)
	assert.Equal(t, http.StatusBadRequest, err.StatusCode)
	assert.Equal(t, "invalid IP address", err.Message)
	assert.Equal(t, "IP address cannot be empty", err.Details)
}

// TestValidateUserIP_InvalidIP tests invalid IP address validation
func TestValidateUserIP_InvalidIP(t *testing.T) {
	tests := []string{
		"256.256.256.256",
		"192.168.1",
		"192.168.1.1.1",
		"not.an.ip.address",
		"192.168.1.a",
		"gggg::1",
	}

	for _, ip := range tests {
		t.Run(ip, func(t *testing.T) {
			err := ValidateUserIP(ip)
			assert.Error(t, err)
			assert.Equal(t, http.StatusBadRequest, err.StatusCode)
			assert.Equal(t, "invalid IP address", err.Message)
		})
	}
}

// TestValidateUserIP_IPWithWhitespace tests IP address with whitespace
func TestValidateUserIP_IPWithWhitespace(t *testing.T) {
	err := ValidateUserIP("  192.168.1.1  ")

	assert.Error(t, err)
	assert.Equal(t, http.StatusBadRequest, err.StatusCode)
}
