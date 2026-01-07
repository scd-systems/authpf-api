package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestLogin_ValidCredentials tests successful login with valid username and password
func TestLogin_ValidCredentials(t *testing.T) {
	// Setup
	e := echo.New()
	config.Rbac.Users = map[string]ConfigFileRbacUsers{
		"testuser": {
			Password: "cf80cd8aed482d5d1527d7dc72fceff84e6326592848447d2dc0b0e87dfc9a90", // "testing"
			Role:     "user",
		},
	}

	body := LoginRequest{
		Username: "testuser",
		Password: "testing",
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/login", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	// Execute
	err := login(c)

	// Assert
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)

	var response LoginResponse
	err = json.Unmarshal(rec.Body.Bytes(), &response)
	require.NoError(t, err)
	assert.NotEmpty(t, response.Token)

	// Verify token is valid
	claims := &JWTClaims{}
	token, err := jwt.ParseWithClaims(response.Token, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})
	require.NoError(t, err)
	assert.True(t, token.Valid)
	assert.Equal(t, "testuser", claims.Username)
}

// TestLogin_InvalidUsername tests login with non-existent username
func TestLogin_InvalidUsername(t *testing.T) {
	// Setup
	e := echo.New()
	config.Rbac.Users = map[string]ConfigFileRbacUsers{
		"testuser": {
			Password: "cf80cd8aed482d5d1527d7dc72fceff84e6326592848447d2dc0b0e87dfc9a90",
			Role:     "user",
		},
	}

	body := LoginRequest{
		Username: "nonexistent",
		Password: "testing",
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/login", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	// Execute
	err := login(c)

	// Assert
	assert.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)

	var response map[string]string
	json.Unmarshal(rec.Body.Bytes(), &response)
	assert.Equal(t, "invalid username or password", response["error"])
}

// TestLogin_InvalidPassword tests login with wrong password
func TestLogin_InvalidPassword(t *testing.T) {
	// Setup
	e := echo.New()
	config.Rbac.Users = map[string]ConfigFileRbacUsers{
		"testuser": {
			Password: "cf80cd8aed482d5d1527d7dc72fceff84e6326592848447d2dc0b0e87dfc9a90", // "testing"
			Role:     "user",
		},
	}

	body := LoginRequest{
		Username: "testuser",
		Password: "wrongpassword",
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/login", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	// Execute
	err := login(c)

	// Assert
	assert.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)

	var response map[string]string
	json.Unmarshal(rec.Body.Bytes(), &response)
	assert.Equal(t, "invalid username or password", response["error"])
}

// TestLogin_EmptyUsername tests login with empty username
func TestLogin_EmptyUsername(t *testing.T) {
	// Setup
	e := echo.New()

	body := LoginRequest{
		Username: "",
		Password: "testing",
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/login", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	// Execute
	err := login(c)

	// Assert
	assert.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)

	var response map[string]string
	json.Unmarshal(rec.Body.Bytes(), &response)
	assert.Equal(t, "invalid credentials", response["error"])
}

// TestLogin_EmptyPassword tests login with empty password
func TestLogin_EmptyPassword(t *testing.T) {
	// Setup
	e := echo.New()

	body := LoginRequest{
		Username: "testuser",
		Password: "",
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/login", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	// Execute
	err := login(c)

	// Assert
	assert.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)

	var response map[string]string
	json.Unmarshal(rec.Body.Bytes(), &response)
	assert.Equal(t, "invalid credentials", response["error"])
}

// TestLogin_InvalidJSON tests login with invalid JSON payload
func TestLogin_InvalidJSON(t *testing.T) {
	// Setup
	e := echo.New()

	req := httptest.NewRequest(http.MethodPost, "/login", bytes.NewReader([]byte("invalid json")))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	// Execute
	err := login(c)

	// Assert
	assert.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, rec.Code)

	var response map[string]string
	json.Unmarshal(rec.Body.Bytes(), &response)
	assert.Equal(t, "invalid request", response["error"])
}

// TestJWTMiddleware_ValidToken tests JWT middleware with valid token
func TestJWTMiddleware_ValidToken(t *testing.T) {
	// Setup
	e := echo.New()

	// Create valid token
	claims := &JWTClaims{
		Username: "testuser",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, _ := token.SignedString(jwtSecret)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/authpf/activate", nil)
	req.Header.Set("Authorization", "Bearer "+tokenString)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	handlerCalled := false
	nextHandler := func(c echo.Context) error {
		handlerCalled = true
		username, ok := c.Get("username").(string)
		assert.True(t, ok)
		assert.Equal(t, "testuser", username)
		return c.String(http.StatusOK, "OK")
	}

	// Execute
	middleware := jwtMiddleware(nextHandler)
	err := middleware(c)

	// Assert
	assert.NoError(t, err)
	assert.True(t, handlerCalled)
	assert.Equal(t, http.StatusOK, rec.Code)
}

// TestJWTMiddleware_MissingAuthHeader tests JWT middleware without Authorization header
func TestJWTMiddleware_MissingAuthHeader(t *testing.T) {
	// Setup
	e := echo.New()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/authpf/activate", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	nextHandler := func(c echo.Context) error {
		return c.String(http.StatusOK, "OK")
	}

	// Execute
	middleware := jwtMiddleware(nextHandler)
	err := middleware(c)

	// Assert
	assert.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)

	var response map[string]string
	json.Unmarshal(rec.Body.Bytes(), &response)
	assert.Equal(t, "missing authorization header", response["error"])
}

// TestJWTMiddleware_InvalidAuthFormat tests JWT middleware with invalid Authorization format
func TestJWTMiddleware_InvalidAuthFormat(t *testing.T) {
	// Setup
	e := echo.New()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/authpf/activate", nil)
	req.Header.Set("Authorization", "InvalidFormat token")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	nextHandler := func(c echo.Context) error {
		return c.String(http.StatusOK, "OK")
	}

	// Execute
	middleware := jwtMiddleware(nextHandler)
	err := middleware(c)

	// Assert
	assert.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)

	var response map[string]string
	json.Unmarshal(rec.Body.Bytes(), &response)
	assert.Equal(t, "invalid authorization format", response["error"])
}

// TestJWTMiddleware_InvalidToken tests JWT middleware with invalid token
func TestJWTMiddleware_InvalidToken(t *testing.T) {
	// Setup
	e := echo.New()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/authpf/activate", nil)
	req.Header.Set("Authorization", "Bearer invalidtoken")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	nextHandler := func(c echo.Context) error {
		return c.String(http.StatusOK, "OK")
	}

	// Execute
	middleware := jwtMiddleware(nextHandler)
	err := middleware(c)

	// Assert
	assert.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)

	var response map[string]string
	json.Unmarshal(rec.Body.Bytes(), &response)
	assert.Equal(t, "invalid token", response["error"])
}

// TestJWTMiddleware_ExpiredToken tests JWT middleware with expired token
func TestJWTMiddleware_ExpiredToken(t *testing.T) {
	// Setup
	e := echo.New()

	// Create expired token
	claims := &JWTClaims{
		Username: "testuser",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(-time.Hour)), // Expired 1 hour ago
			IssuedAt:  jwt.NewNumericDate(time.Now().Add(-2 * time.Hour)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, _ := token.SignedString(jwtSecret)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/authpf/activate", nil)
	req.Header.Set("Authorization", "Bearer "+tokenString)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	nextHandler := func(c echo.Context) error {
		return c.String(http.StatusOK, "OK")
	}

	// Execute
	middleware := jwtMiddleware(nextHandler)
	err := middleware(c)

	// Assert
	assert.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)

	var response map[string]string
	json.Unmarshal(rec.Body.Bytes(), &response)
	assert.Equal(t, "invalid token", response["error"])
}
