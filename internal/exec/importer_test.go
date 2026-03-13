package exec

import (
	"errors"
	"os"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/scd-systems/authpf-api/internal/authpf"
	"github.com/scd-systems/authpf-api/pkg/config"
	"github.com/stretchr/testify/assert"
)

// TestCalculateAnchorExpire_ValidTimeout tests successful expiration time calculation
func TestCalculateAnchorExpire_ValidTimeout(t *testing.T) {
	beforeTime := time.Now().Add(1 * time.Hour)

	expiresAt, err := CalculateAnchorExpire("1h")

	afterTime := time.Now().Add(1 * time.Hour)

	assert.NoError(t, err)
	assert.True(t, expiresAt.After(beforeTime) || expiresAt.Equal(beforeTime))
	assert.True(t, expiresAt.Before(afterTime.Add(1*time.Second)) || expiresAt.Equal(afterTime))
}

// TestCalculateAnchorExpire_InvalidTimeout tests with invalid timeout format
func TestCalculateAnchorExpire_InvalidTimeout(t *testing.T) {
	_, err := CalculateAnchorExpire("invalid")

	assert.Error(t, err)
}

// TestCalculateAnchorExpire_VariousTimeouts tests with various valid timeout formats
func TestCalculateAnchorExpire_VariousTimeouts(t *testing.T) {
	tests := []struct {
		name    string
		timeout string
		valid   bool
	}{
		{"1 minute", "1m", true},
		{"30 minutes", "30m", true},
		{"1 hour", "1h", true},
		{"24 hours", "24h", true},
		{"invalid format", "invalid", false},
		{"empty string", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			expiresAt, err := CalculateAnchorExpire(tt.timeout)

			if tt.valid {
				assert.NoError(t, err)
				assert.False(t, expiresAt.IsZero())
				assert.True(t, expiresAt.After(time.Now()))
			} else {
				assert.Error(t, err)
			}
		})
	}
}

// Helper function to create a test Exec instance for importer tests
func createTestExecForImporter(t *testing.T) *Exec {
	logger := zerolog.New(os.Stderr).With().Timestamp().Logger()
	db := authpf.New()
	cfg := &config.ConfigFile{
		AuthPF: config.ConfigFileAuthPF{
			Timeout: "1h",
		},
		Rbac: config.ConfigFileRbac{
			Users: map[string]config.ConfigFileRbacUsers{
				"user1": {Password: "test", Role: "user", UserID: 0},
				"user2": {Password: "test", Role: "user", UserID: 200},
				"user4": {Password: "test", Role: "user", UserID: 400},
				"user5": {Password: "test", Role: "user", UserID: 2222},
			},
		},
	}
	nExec, err := New(logger, cfg, db)
	assert.NoError(t, err)
	return nExec
}

// TestParsePfctlOutput verifies that parsePfctlOutput correctly parses the
// command output, creates map entries for lines that contain a user ID, and
// skips lines without an ID.
func TestParsePfctlOutput(t *testing.T) {
	// Sample output that mimics the real pfctl command.
	const sample = `  authpf
  authpf/user1(0)
  authpf/user2(200)
  authpf/user3
  authpf/user4(400)
  authpf/user5(2222)
Anchor 'authpf' not found.
	authpf/userA(noid)
	authpf/userB(notanumber)
	authpf/userC(123
  authpf/
  autx/userx
  /asd
  authpf/)
  (/)
`
	testResult := &SystemCommandResult{
		Stdout: sample,
	}

	exec := createTestExecForImporter(t)
	err := exec.parsePfctlOutput(testResult)
	assert.NoError(t, err)

	// Expected map entries (user3 should be omitted because it lacks an ID).
	expected := map[string]int{
		"user1": 0,
		"user2": 200,
		"user4": 400,
		"user5": 2222,
	}

	if len(*exec.db) != len(expected) {
		t.Fatalf("expected %d entries, got %d", len(expected), len(*exec.db))
	}

	for user, expID := range expected {
		rule, ok := (*exec.db)[user]
		if !ok {
			t.Fatalf("expected user %q to be present", user)
		}
		if rule.UserID != expID {
			t.Fatalf("user %q: expected ID %d, got %d", user, expID, rule.UserID)
		}
	}
}

// TestParsePfctlOutputError ensures that an error from the system command is propagated.
func TestParsePfctlOutputError(t *testing.T) {
	cmdErr := errors.New("command failed")
	testResult := &SystemCommandResult{Error: cmdErr}

	exec := createTestExecForImporter(t)
	err := exec.parsePfctlOutput(testResult)
	assert.Error(t, err)
	assert.Equal(t, cmdErr, err)
}

// TestParsePfctlOutputEmptyOutput verifies that an empty stdout results in an empty anchorsDB without error.
func TestParsePfctlOutputEmptyOutput(t *testing.T) {
	testResult := &SystemCommandResult{Stdout: ""}

	exec := createTestExecForImporter(t)
	err := exec.parsePfctlOutput(testResult)
	assert.NoError(t, err)
	if len(*exec.db) != 0 {
		t.Fatalf("expected anchorsDB to be empty, got %d entries", len(*exec.db))
	}
}

// TestParsePfctlOutputMalformedLines checks that malformed lines are ignored.
func TestParsePfctlOutputMalformedLines(t *testing.T) {
	const sample = `authpf/badline
	authpf/userA(noid)
	authpf/userB(notanumber)
	authpf/userC(123
  authpf/
  autx/userx
  /asd
  authpf/)
  (/)`
	testResult := &SystemCommandResult{Stdout: sample}

	exec := createTestExecForImporter(t)
	err := exec.parsePfctlOutput(testResult)
	assert.NoError(t, err)
	// Only valid lines should be added; in this sample none are valid.
	if len(*exec.db) != 0 {
		t.Fatalf("expected no valid entries, got %d", len(*exec.db))
	}
}
