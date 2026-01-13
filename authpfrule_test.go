package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/rs/zerolog"
)

// TestBuildActivateAuthPFRule_Success tests successful building of an activate rule
func TestBuildActivateAuthPFRule_Success(t *testing.T) {
	// Setup
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/authpf/activate?timeout=1h&authpf_username=testuser", strings.NewReader(`{}`))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.Set("username", "admin")
	c.Set("logger", zerolog.Logger{})

	// Mock config
	config.Rbac.Roles = map[string]ConfigFileRbacRoles{
		"admin": {Permissions: []string{RBAC_ACTIVATE_OTHER_RULE}},
		"user":  {Permissions: []string{RBAC_ACTIVATE_OWN_RULE}},
	}

	config.Rbac.Users = map[string]ConfigFileRbacUsers{
		"admin":    {Role: "admin", UserID: 1},
		"testuser": {Role: "user", UserID: 2},
	}

	// Execute
	r, err := SetAuthPFRule(c, zerolog.Logger{}, SESSION_REGISTER)

	// Assert
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if r == nil {
		t.Fatal("Expected rule to be built, got nil")
	}
	if r.Username != "testuser" {
		t.Errorf("Expected username 'testuser', got '%s'", r.Username)
	}
	if r.UserID != 2 {
		t.Errorf("Expected UserID 2, got %d", r.UserID)
	}
	if r.Timeout != "1h" {
		t.Errorf("Expected timeout '1h', got '%s'", r.Timeout)
	}
	if r.ExpiresAt.IsZero() {
		t.Error("Expected ExpiresAt to be set")
	}
}

// TestBuildActivateAuthPFRule_InvalidUsername tests with missing username in token
func TestBuildActivateAuthPFRule_InvalidUsername(t *testing.T) {
	// Setup
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/authpf/activate", strings.NewReader(`{}`))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.Set("logger", zerolog.Logger{})

	// Execute
	r, err := SetAuthPFRule(c, zerolog.Logger{}, SESSION_REGISTER)

	// Assert
	if err == nil {
		t.Fatal("Expected validation error, got nil")
	}
	if r != nil {
		t.Fatal("Expected rule to be nil on error")
	}
	if err.StatusCode != http.StatusUnauthorized {
		t.Errorf("Expected status code %d, got %d", http.StatusUnauthorized, err.StatusCode)
	}
}

// TestBuildActivateAuthPFRule_InvalidTimeout tests with invalid timeout format
func TestBuildActivateAuthPFRule_InvalidTimeout(t *testing.T) {
	// Setup
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/authpf/activate?timeout=invalid", strings.NewReader(`{}`))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.Set("username", "admin")
	c.Set("logger", zerolog.Logger{})

	// Execute
	r, err := SetAuthPFRule(c, zerolog.Logger{}, SESSION_REGISTER)

	// Assert
	if err == nil {
		t.Fatal("Expected validation error for invalid timeout, got nil")
	}
	if r != nil {
		t.Fatal("Expected rule to be nil on error")
	}
	if err.StatusCode != http.StatusBadRequest {
		t.Errorf("Expected status code %d, got %d", http.StatusBadRequest, err.StatusCode)
	}
}

// TestBuildActivateAuthPFRule_TimeoutTooShort tests with timeout less than 1 minute
func TestBuildActivateAuthPFRule_TimeoutTooShort(t *testing.T) {
	// Setup
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/authpf/activate?timeout=30s", strings.NewReader(`{}`))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.Set("username", "admin")
	c.Set("logger", zerolog.Logger{})

	// Execute
	r, err := SetAuthPFRule(c, zerolog.Logger{}, SESSION_REGISTER)

	// Assert
	if err == nil {
		t.Fatal("Expected validation error for timeout too short, got nil")
	}
	if r != nil {
		t.Fatal("Expected rule to be nil on error")
	}
}

// TestBuildActivateAuthPFRule_TimeoutTooLong tests with timeout exceeding 24 hours
func TestBuildActivateAuthPFRule_TimeoutTooLong(t *testing.T) {
	// Setup
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/authpf/activate?timeout=48h", strings.NewReader(`{}`))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.Set("username", "admin")
	c.Set("logger", zerolog.Logger{})

	// Execute
	r, err := SetAuthPFRule(c, zerolog.Logger{}, SESSION_REGISTER)

	// Assert
	if err == nil {
		t.Fatal("Expected validation error for timeout too long, got nil")
	}
	if r != nil {
		t.Fatal("Expected rule to be nil on error")
	}
}

// TestBuildActivateAuthPFRule_ExpiresAtCalculation tests that ExpiresAt is correctly calculated
func TestBuildActivateAuthPFRule_ExpiresAtCalculation(t *testing.T) {
	// Setup
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/authpf/activate?timeout=1h", strings.NewReader(`{}`))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.Set("username", "admin")
	c.Set("logger", zerolog.Logger{})

	config.Rbac.Users = map[string]ConfigFileRbacUsers{
		"admin": {Role: "admin", UserID: 1},
	}

	beforeTime := time.Now().Add(1 * time.Hour)

	// Execute
	r, err := SetAuthPFRule(c, zerolog.Logger{}, SESSION_REGISTER)

	afterTime := time.Now().Add(1 * time.Hour)

	// Assert
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if r.ExpiresAt.Before(beforeTime) || r.ExpiresAt.After(afterTime.Add(1*time.Second)) {
		t.Errorf("ExpiresAt not correctly calculated: %v", r.ExpiresAt)
	}
}

// TestValidateActivateAuthPFRule_Success tests successful validation
func TestValidateActivateAuthPFRule_Success(t *testing.T) {
	// Setup
	r := &AuthPFRule{
		Username:  "testuser",
		UserIP:    "192.168.1.1",
		UserID:    1,
		Timeout:   "1h",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}

	config.Rbac.Users = map[string]ConfigFileRbacUsers{
		"testuser": {Role: "user"},
	}
	config.Rbac.Roles = map[string]ConfigFileRbacRoles{
		"user": {Permissions: []string{"set_own_rules"}},
	}

	// Execute
	err := ValidateAuthPFRule(r, zerolog.Logger{}, SESSION_REGISTER)

	// Assert
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
}

// TestValidateActivateAuthPFRule_SessionAlreadyExists tests when session already exists
func TestValidateActivateAuthPFRule_SessionAlreadyExists(t *testing.T) {
	// Setup
	r := &AuthPFRule{
		Username: "testuser",
		UserIP:   "192.168.1.1",
		UserID:   1,
	}

	// Pre-populate rulesdb to simulate existing session
	rulesdb["testuser"] = r

	config.Rbac.Users = map[string]ConfigFileRbacUsers{
		"testuser": {Role: "user"},
	}
	config.Rbac.Roles = map[string]ConfigFileRbacRoles{
		"user": {Permissions: []string{"set_own_rules"}},
	}

	// Execute
	err := ValidateAuthPFRule(r, zerolog.Logger{}, SESSION_REGISTER)

	// Assert
	if err == nil {
		t.Fatal("Expected validation error for existing session, got nil")
	}
	if err.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("Expected status code %d, got %d", http.StatusMethodNotAllowed, err.StatusCode)
	}

	// Cleanup
	delete(rulesdb, "testuser")
}

// TestValidateActivateAuthPFRule_MissingPermission tests when user lacks permission
func TestValidateActivateAuthPFRule_MissingPermission(t *testing.T) {
	// Setup
	r := &AuthPFRule{
		Username: "testuser",
		UserIP:   "192.168.1.1",
		UserID:   1,
	}

	config.Rbac.Users = map[string]ConfigFileRbacUsers{
		"testuser": {Role: "user"},
	}
	config.Rbac.Roles = map[string]ConfigFileRbacRoles{
		"user": {Permissions: []string{}}, // No permissions
	}

	// Execute
	err := ValidateAuthPFRule(r, zerolog.Logger{}, SESSION_REGISTER)

	// Assert
	if err == nil {
		t.Fatal("Expected validation error for missing permission, got nil")
	}
	if err.StatusCode != http.StatusForbidden {
		t.Errorf("Expected status code %d, got %d", http.StatusForbidden, err.StatusCode)
	}
}

// TestBuildDeactivateAuthPFRule_Success tests successful building of a deactivate rule
func TestBuildDeactivateAuthPFRule_Success(t *testing.T) {
	// Setup
	e := echo.New()
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/authpf/activate?authpf_username=testuser", strings.NewReader(`{}`))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.Set("username", "testuser")
	c.Set("logger", zerolog.Logger{})

	config.Rbac.Roles = map[string]ConfigFileRbacRoles{
		"admin": {Permissions: []string{RBAC_DEACTIVATE_OTHER_RULE}},
		"user":  {Permissions: []string{RBAC_DEACTIVATE_OWN_RULE}},
	}
	config.Rbac.Users = map[string]ConfigFileRbacUsers{
		"admin":    {Role: "admin", UserID: 1},
		"testuser": {Role: "user", UserID: 2},
	}

	// Execute
	r, err := SetAuthPFRule(c, zerolog.Logger{}, SESSION_UNREGISTER)

	// Assert
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if r == nil {
		t.Fatal("Expected rule to be built, got nil")
	}
	if r.Username != "testuser" {
		t.Errorf("Expected username 'testuser', got '%s'", r.Username)
	}
	if r.UserID != 2 {
		t.Errorf("Expected UserID 2, got %d", r.UserID)
	}
}

// TestBuildDeactivateAuthPFRule_InvalidUsername tests with missing username in token
func TestBuildDeactivateAuthPFRule_InvalidUsername(t *testing.T) {
	// Setup
	e := echo.New()
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/authpf/activate", strings.NewReader(`{}`))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.Set("logger", zerolog.Logger{})

	// Execute
	r, err := SetAuthPFRule(c, zerolog.Logger{}, SESSION_UNREGISTER)

	// Assert
	if err == nil {
		t.Fatal("Expected validation error, got nil")
	}
	if r != nil {
		t.Fatal("Expected rule to be nil on error")
	}
	if err.StatusCode != http.StatusUnauthorized {
		t.Errorf("Expected status code %d, got %d", http.StatusUnauthorized, err.StatusCode)
	}
}

// TestValidateDeactivateAuthPFRule_Success tests successful validation
func TestValidateDeactivateAuthPFRule_Success(t *testing.T) {
	// Setup
	r := &AuthPFRule{
		Username: "testuser",
		UserIP:   "192.168.1.1",
		UserID:   1,
	}

	// Pre-populate rulesdb to simulate existing session
	rulesdb["testuser"] = r

	config.Rbac.Users = map[string]ConfigFileRbacUsers{
		"testuser": {Role: "user"},
	}
	config.Rbac.Roles = map[string]ConfigFileRbacRoles{
		"user": {Permissions: []string{"delete_own_rules"}},
	}

	// Execute
	err := ValidateAuthPFRule(r, zerolog.Logger{}, SESSION_UNREGISTER)

	// Assert
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Cleanup
	delete(rulesdb, "testuser")
}

// TestValidateDeactivateAuthPFRule_SessionNotExists tests when session doesn't exist
func TestValidateDeactivateAuthPFRule_SessionNotExists(t *testing.T) {
	// Setup
	r := &AuthPFRule{
		Username: "testuser",
		UserIP:   "192.168.1.1",
		UserID:   1,
	}

	config.Rbac.Users = map[string]ConfigFileRbacUsers{
		"testuser": {Role: "user"},
	}
	config.Rbac.Roles = map[string]ConfigFileRbacRoles{
		"user": {Permissions: []string{"delete_own_rules"}},
	}

	// Execute
	err := ValidateAuthPFRule(r, zerolog.Logger{}, SESSION_UNREGISTER)

	// Assert
	if err == nil {
		t.Fatal("Expected validation error for non-existing session, got nil")
	}
	if err.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("Expected status code %d, got %d", http.StatusMethodNotAllowed, err.StatusCode)
	}
}

// TestValidateDeactivateAuthPFRule_MissingPermission tests when user lacks permission
func TestValidateDeactivateAuthPFRule_MissingPermission(t *testing.T) {
	// Setup
	r := &AuthPFRule{
		Username: "testuser",
		UserIP:   "192.168.1.1",
		UserID:   1,
	}

	// Pre-populate rulesdb to simulate existing session
	rulesdb["testuser"] = r

	config.Rbac.Users = map[string]ConfigFileRbacUsers{
		"testuser": {Role: "user"},
	}
	config.Rbac.Roles = map[string]ConfigFileRbacRoles{
		"user": {Permissions: []string{}}, // No permissions
	}

	// Execute
	err := ValidateAuthPFRule(r, zerolog.Logger{}, SESSION_UNREGISTER)

	// Assert
	if err == nil {
		t.Fatal("Expected validation error for missing permission, got nil")
	}
	if err.StatusCode != http.StatusForbidden {
		t.Errorf("Expected status code %d, got %d", http.StatusForbidden, err.StatusCode)
	}

	// Cleanup
	delete(rulesdb, "testuser")
}
