package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/labstack/echo/v5"
	"github.com/rs/zerolog"
	"github.com/scd-systems/authpf-api/internal/auth"
	"github.com/scd-systems/authpf-api/internal/authpf"
	"github.com/scd-systems/authpf-api/pkg/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// generateTestConfig creates a temporary config file for E2E testing
func generateTestConfig(t *testing.T, port uint16) string {
	t.Helper()

	hash, err := auth.GeneratePasswordHash("testpassword123")
	require.NoError(t, err)

	tmpDir := t.TempDir()
	rulesDir := filepath.Join(tmpDir, "rules")
	require.NoError(t, os.MkdirAll(rulesDir, 0755))

	// Create rules file for testuser
	testuserRulesDir := filepath.Join(rulesDir, "testuser")
	require.NoError(t, os.MkdirAll(testuserRulesDir, 0755))
	rulesFile := filepath.Join(testuserRulesDir, "rules")
	require.NoError(t, os.WriteFile(rulesFile, []byte("# test rules\npass all\n"), 0644))

	// Create mock sudo script that just runs the command
	mockSudoPath := filepath.Join(tmpDir, "sudo")
	require.NoError(t, os.WriteFile(mockSudoPath, []byte("#!/bin/bash\nexec \"$@\"\n"), 0755))

	// Add tmpDir to PATH so mock sudo is found
	oldPath := os.Getenv("PATH")
	os.Setenv("PATH", tmpDir+":"+oldPath)
	t.Cleanup(func() { os.Setenv("PATH", oldPath) })

	yamlContent := fmt.Sprintf(`server:
  bind: 127.0.0.1
  port: %d
  logfile: "/tmp/authpf-api-e2e.log"
  elevatorMode: "sudo"
  jwtTokenTimeout: "1h"
  jwtSecret: "e2e-test-secret-key-12345"

defaults:
  pfctlBinary: "echo"

authpf:
  timeout: "1h"
  userRulesRootFolder: "%s"
  userRulesFile: "rules"
  anchorName: "authpf"
  flushFilter:
    - "rules"
    - "nat"

rbac:
  roles:
    admin:
      permissions:
        - "activate_own_rules"
        - "activate_other_rules"
        - "deactivate_own_rules"
        - "deactivate_other_rules"
        - "view_own_rules"
        - "view_other_rules"
    user:
      permissions:
        - "activate_own_rules"
        - "deactivate_own_rules"
        - "view_own_rules"
  users:
    testuser:
      password: "%s"
      role: "admin"
      userId: 1000
`, port, rulesDir, hash)

	cfgPath := filepath.Join(tmpDir, "authpf-api.conf")
	require.NoError(t, os.WriteFile(cfgPath, []byte(yamlContent), 0640))

	return cfgPath
}

// newTestServer creates a configured server instance for E2E testing
func newTestServer(t *testing.T, fixedPort uint16) (*Server, *echo.Echo) {
	t.Helper()

	cfgPath := generateTestConfig(t, fixedPort)

	cfg := config.New()
	require.NoError(t, cfg.LoadConfig(cfgPath))

	db := authpf.New()
	logger := zerolog.New(zerolog.ConsoleWriter{Out: io.Discard})

	srv := &Server{
		config: cfg,
		db:     db,
		logger: logger,
	}

	// Set global JWT secret
	jwtSecret = []byte(cfg.Server.JwtSecret)

	// Create Echo instance
	e := echo.New()
	require.NoError(t, srv.SetupServer(e))

	return srv, e
}

// startTestServer starts an Echo server in the background and returns the base URL
func startTestServer(t *testing.T, srv *Server, e *echo.Echo) string {
	t.Helper()

	addr := fmt.Sprintf("%s:%d", srv.config.Server.Bind, srv.config.Server.Port)
	sc := echo.StartConfig{
		Address:    addr,
		HideBanner: true,
		BeforeServeFunc: func(s *http.Server) error {
			srv.httpServer = s
			return nil
		},
	}

	go func() {
		_ = sc.Start(context.Background(), e)
	}()

	// Wait for server to be ready
	time.Sleep(200 * time.Millisecond)

	return fmt.Sprintf("http://%s", addr)
}

// loginAs performs a login and returns the JWT token
func loginAs(t *testing.T, baseURL, username, password string) string {
	t.Helper()

	// Double-hash: SHA256 first (as hex string), then bcrypt on server side
	sha256Hash := sha256.Sum256([]byte(password))
	sha256Hex := hex.EncodeToString(sha256Hash[:])

	loginReq := map[string]string{
		"username": username,
		"password": sha256Hex,
	}
	loginBody, err := json.Marshal(loginReq)
	require.NoError(t, err)

	resp, err := http.Post(baseURL+"/login", "application/json", bytes.NewReader(loginBody))
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)

	var loginResp struct {
		Token string `json:"token"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&loginResp))
	return loginResp.Token
}

// activateAs performs an anchor activation
func activateAs(t *testing.T, baseURL, token, username string) {
	t.Helper()
	activateReq := map[string]string{"username": username}
	activateBody, err := json.Marshal(activateReq)
	require.NoError(t, err)

	req, err := http.NewRequest("POST", baseURL+"/api/v1/authpf/activate", bytes.NewReader(activateBody))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusCreated, resp.StatusCode)
}

// TestE2E_HealthCheck tests the health check endpoint
func TestE2E_HealthCheck(t *testing.T) {
	srv, e := newTestServer(t, 19879)
	baseURL := startTestServer(t, srv, e)

	resp, err := http.Get(baseURL + "/")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode, "Health check should return 200")

	var healthResp map[string]interface{}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&healthResp))
	assert.Equal(t, "running", healthResp["Status"])
}

// TestE2E_LoginSuccess tests successful login
func TestE2E_LoginSuccess(t *testing.T) {
	srv, e := newTestServer(t, 19881)
	baseURL := startTestServer(t, srv, e)

	token := loginAs(t, baseURL, "testuser", "testpassword123")
	assert.NotEmpty(t, token, "Login should return a JWT token")
}

// TestE2E_LoginInvalidCredentials tests that login fails with wrong password
func TestE2E_LoginInvalidCredentials(t *testing.T) {
	srv, e := newTestServer(t, 19882)
	baseURL := startTestServer(t, srv, e)

	loginReq := map[string]string{
		"username": "testuser",
		"password": "wrongpassword",
	}
	loginBody, err := json.Marshal(loginReq)
	require.NoError(t, err)

	resp, err := http.Post(baseURL+"/login", "application/json", bytes.NewReader(loginBody))
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode, "Login with wrong password should return 401")
}

// TestE2E_LoginMissingFields tests that login fails with missing fields
func TestE2E_LoginMissingFields(t *testing.T) {
	srv, e := newTestServer(t, 19883)
	baseURL := startTestServer(t, srv, e)

	loginReq := map[string]string{
		"username": "testuser",
	}
	loginBody, err := json.Marshal(loginReq)
	require.NoError(t, err)

	resp, err := http.Post(baseURL+"/login", "application/json", bytes.NewReader(loginBody))
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode, "Login with missing password should return 401")
}

// TestE2E_ActivateWithoutToken tests that activate fails without JWT
func TestE2E_ActivateWithoutToken(t *testing.T) {
	srv, e := newTestServer(t, 19884)
	baseURL := startTestServer(t, srv, e)

	activateReq := map[string]string{"username": "testuser"}
	activateBody, err := json.Marshal(activateReq)
	require.NoError(t, err)

	resp, err := http.Post(baseURL+"/api/v1/authpf/activate", "application/json", bytes.NewReader(activateBody))
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode, "Activate without token should return 401")
}

// TestE2E_LoginAndActivate performs a full login → activate flow
func TestE2E_LoginAndActivate(t *testing.T) {
	srv, e := newTestServer(t, 19885)
	baseURL := startTestServer(t, srv, e)

	// Step 1: Login
	token := loginAs(t, baseURL, "testuser", "testpassword123")
	assert.NotEmpty(t, token, "Login should return a JWT token")

	// Step 2: Activate anchor
	activateAs(t, baseURL, token, "testuser")
}

// TestE2E_GetStatus tests GET /api/v1/authpf/activate after activation
func TestE2E_GetStatus(t *testing.T) {
	srv, e := newTestServer(t, 19886)
	baseURL := startTestServer(t, srv, e)

	// Login
	token := loginAs(t, baseURL, "testuser", "testpassword123")
	require.NotEmpty(t, token)

	// Activate
	activateAs(t, baseURL, token, "testuser")

	// GET status
	req, err := http.NewRequest("GET", baseURL+"/api/v1/authpf/activate", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode, "GET status should return 200")

	var statusResp map[string]interface{}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&statusResp))
	assert.NotNil(t, statusResp["anchors"])
	assert.NotEmpty(t, statusResp["server_time"])
}

// TestE2E_InfoEndpoint tests the /info endpoint
func TestE2E_InfoEndpoint(t *testing.T) {
	srv, e := newTestServer(t, 19887)
	baseURL := startTestServer(t, srv, e)

	resp, err := http.Get(baseURL + "/info")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode, "Info endpoint should return 200")

	var infoResp map[string]string
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&infoResp))
	assert.NotEmpty(t, infoResp["server_version"])
	assert.NotEmpty(t, infoResp["api_version"])
}

// TestE2E_ActivateDuplicate tests that activating an already active anchor fails
func TestE2E_ActivateDuplicate(t *testing.T) {
	srv, e := newTestServer(t, 19888)
	baseURL := startTestServer(t, srv, e)

	token := loginAs(t, baseURL, "testuser", "testpassword123")
	require.NotEmpty(t, token)

	// First activation should succeed
	activateAs(t, baseURL, token, "testuser")

	// Second activation should fail
	activateReq := map[string]string{"username": "testuser"}
	activateBody, err := json.Marshal(activateReq)
	require.NoError(t, err)

	req, err := http.NewRequest("POST", baseURL+"/api/v1/authpf/activate", bytes.NewReader(activateBody))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusAlreadyReported, resp.StatusCode, "Duplicate activation should return 507")
}
