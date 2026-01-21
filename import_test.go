package main

import (
	"testing"

	"errors"

	"github.com/stretchr/testify/assert"
)

// TestParseExecOutput verifies that parseExecOutput correctly parses the
// command output, creates map entries for lines that contain a user ID, and
// skips lines without an ID.
func TestParseExecOutput(t *testing.T) {
	// Sample output that mimics the real exec command.
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
	testResult := SystemCommandResult{
		Stdout: sample,
	}

	err := parseAuthpf(testResult)
	assert.NoError(t, err)

	// Expected map entries (user3 should be omitted because it lacks an ID).
	expected := map[string]int{
		"user1": 0,
		"user2": 200,
		"user4": 400,
		"user5": 2222,
	}

	if len(rulesdb) != len(expected) {
		t.Fatalf("expected %d entries, got %d", len(expected), len(rulesdb))
	}

	for user, expID := range expected {
		rule, ok := rulesdb[user]
		if !ok {
			t.Fatalf("expected user %q to be present", user)
		}
		if rule.UserID != expID {
			t.Fatalf("user %q: expected ID %d, got %d", user, expID, rule.UserID)
		}
	}
}

// TestParseAuthpfError ensures that an error from the system command is propagated.
func TestParseAuthpfError(t *testing.T) {
	cmdErr := errors.New("command failed")
	testResult := SystemCommandResult{Error: cmdErr}
	err := parseAuthpf(testResult)
	assert.Error(t, err)
	assert.Equal(t, cmdErr, err)
}

// TestParseAuthpfEmptyOutput verifies that an empty stdout results in an empty rulesdb without error.
func TestParseAuthpfEmptyOutput(t *testing.T) {
	testResult := SystemCommandResult{Stdout: ""}
	err := parseAuthpf(testResult)
	assert.NoError(t, err)
	if len(rulesdb) != 0 {
		t.Fatalf("expected rulesdb to be empty, got %d entries", len(rulesdb))
	}
}

// TestParseAuthpfMalformedLines checks that malformed lines are ignored.
func TestParseAuthpfMalformedLines(t *testing.T) {
	const sample = `authpf/badline
	authpf/userA(noid)
	authpf/userB(notanumber)
	authpf/userC(123
  authpf/
  autx/userx
  /asd
  authpf/)
  (/)`
	testResult := SystemCommandResult{Stdout: sample}
	err := parseAuthpf(testResult)
	assert.NoError(t, err)
	// Only valid lines should be added; in this sample none are valid.
	if len(rulesdb) != 0 {
		t.Fatalf("expected no valid entries, got %d", len(rulesdb))
	}
}
