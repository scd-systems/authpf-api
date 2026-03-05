package server

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGetVersionInfo tests that GetVersionInfo returns a correctly populated VersionInfo struct
func TestGetVersionInfo(t *testing.T) {
	// Set known values for the test
	originalVersion := Version
	Version = "v1.2.3-test"
	defer func() { Version = originalVersion }()

	info := GetVersionInfo()

	assert.Equal(t, "v1.2.3-test", info.ServerVersion, "ServerVersion should match the Version variable")
	assert.NotEmpty(t, info.APIVersion, "APIVersion should not be empty")
}

// TestGetVersionInfoDefaultVersion tests the default "dev" version
func TestGetVersionInfoDefaultVersion(t *testing.T) {
	originalVersion := Version
	Version = "dev"
	defer func() { Version = originalVersion }()

	info := GetVersionInfo()

	assert.Equal(t, "dev", info.ServerVersion)
	assert.NotEmpty(t, info.APIVersion)
}

// TestVersionInfoJSONSerialization tests that VersionInfo serializes to the expected JSON keys
func TestVersionInfoJSONSerialization(t *testing.T) {
	tests := []struct {
		name          string
		serverVersion string
		wantKeys      []string
	}{
		{
			name:          "snake_case json keys",
			serverVersion: "v2.0.0",
			wantKeys:      []string{"server_version", "api_version"},
		},
		{
			name:          "dev version",
			serverVersion: "dev",
			wantKeys:      []string{"server_version", "api_version"},
		},
		{
			name:          "git tag version",
			serverVersion: "v1.0.0-rc1-dirty",
			wantKeys:      []string{"server_version", "api_version"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			originalVersion := Version
			Version = tt.serverVersion
			defer func() { Version = originalVersion }()

			info := GetVersionInfo()
			jsonData, err := json.Marshal(info)
			require.NoError(t, err, "JSON marshaling should not fail")

			var result map[string]string
			err = json.Unmarshal(jsonData, &result)
			require.NoError(t, err, "JSON unmarshaling should not fail")

			for _, key := range tt.wantKeys {
				_, exists := result[key]
				assert.True(t, exists, "JSON output should contain key %q", key)
			}

			// Ensure PascalCase keys are NOT present
			assert.NotContains(t, result, "ServerVersion", "JSON should not use PascalCase key 'ServerVersion'")
			assert.NotContains(t, result, "APIVersion", "JSON should not use PascalCase key 'APIVersion'")

			// Verify the actual value
			assert.Equal(t, tt.serverVersion, result["server_version"])
		})
	}
}

// TestDisplayVersionInfo tests that displayVersionInfo writes valid JSON to stdout
func TestDisplayVersionInfo(t *testing.T) {
	originalVersion := Version
	Version = "v1.0.0"
	defer func() { Version = originalVersion }()

	// Capture stdout
	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stdout = w

	displayVersionInfo()

	w.Close()
	os.Stdout = oldStdout

	var buf bytes.Buffer
	_, err = io.Copy(&buf, r)
	require.NoError(t, err)

	output := buf.String()
	assert.NotEmpty(t, output, "displayVersionInfo should produce output")

	// Verify it is valid JSON
	var result map[string]string
	err = json.Unmarshal([]byte(output), &result)
	require.NoError(t, err, "displayVersionInfo output should be valid JSON, got: %s", output)

	assert.Equal(t, "v1.0.0", result["server_version"])
	assert.NotEmpty(t, result["api_version"])
}

// TestVersionInfoStructFields tests that VersionInfo has the expected fields
func TestVersionInfoStructFields(t *testing.T) {
	info := VersionInfo{
		ServerVersion: "v1.0.0",
		APIVersion:    "1.2",
	}

	assert.Equal(t, "v1.0.0", info.ServerVersion)
	assert.Equal(t, "1.2", info.APIVersion)
}

// TestInfoHTTPHandler tests the GET /info HTTP endpoint
func TestInfoHTTPHandler(t *testing.T) {
	tests := []struct {
		name          string
		serverVersion string
		wantStatus    int
		wantKeys      []string
	}{
		{
			name:          "returns 200 with version info",
			serverVersion: "v1.0.0",
			wantStatus:    http.StatusOK,
			wantKeys:      []string{"server_version", "api_version"},
		},
		{
			name:          "returns dev version",
			serverVersion: "dev",
			wantStatus:    http.StatusOK,
			wantKeys:      []string{"server_version", "api_version"},
		},
		{
			name:          "returns git tag version",
			serverVersion: "v2.3.1-dirty",
			wantStatus:    http.StatusOK,
			wantKeys:      []string{"server_version", "api_version"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			originalVersion := Version
			Version = tt.serverVersion
			defer func() { Version = originalVersion }()

			e := echo.New()
			req := httptest.NewRequest(http.MethodGet, "/info", nil)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)

			err := info(c)
			require.NoError(t, err, "info handler should not return an error")

			assert.Equal(t, tt.wantStatus, rec.Code, "HTTP status code should be 200")
			assert.Equal(t, "application/json", rec.Header().Get("Content-Type"),
				"Content-Type should be application/json")

			var result map[string]string
			err = json.Unmarshal(rec.Body.Bytes(), &result)
			require.NoError(t, err, "response body should be valid JSON, got: %s", rec.Body.String())

			for _, key := range tt.wantKeys {
				_, exists := result[key]
				assert.True(t, exists, "JSON response should contain key %q", key)
			}

			assert.Equal(t, tt.serverVersion, result["server_version"],
				"server_version in response should match Version variable")
			assert.NotEmpty(t, result["api_version"],
				"api_version in response should not be empty")
		})
	}
}

// TestInfoHTTPHandlerConsistencyWithCLI tests that HTTP /info and CLI --version return identical data
func TestInfoHTTPHandlerConsistencyWithCLI(t *testing.T) {
	originalVersion := Version
	Version = "v1.5.0"
	defer func() { Version = originalVersion }()

	// Get data via GetVersionInfo() (used by both CLI and HTTP handler)
	cliInfo := GetVersionInfo()

	// Get data via HTTP handler
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/info", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err := info(c)
	require.NoError(t, err)

	var httpResult VersionInfo
	err = json.Unmarshal(rec.Body.Bytes(), &httpResult)
	require.NoError(t, err, "HTTP response should be valid JSON")

	assert.Equal(t, cliInfo.ServerVersion, httpResult.ServerVersion,
		"CLI and HTTP endpoint must return the same server_version")
	assert.Equal(t, cliInfo.APIVersion, httpResult.APIVersion,
		"CLI and HTTP endpoint must return the same api_version")
}
