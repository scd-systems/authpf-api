package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/scd-systems/authpf-api/pkg/config"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/bcrypt"
)

// TestParseJwtTokenTimeout_ValidMinutes tests parsing valid minutes format
func TestParseJwtTokenTimeout_ValidMinutes(t *testing.T) {
	duration, err := parseJwtTokenTimeout("30m")
	assert.NoError(t, err)
	assert.Equal(t, 30*time.Minute, duration)
}

// TestParseJwtTokenTimeout_ValidHours tests parsing valid hours format
func TestParseJwtTokenTimeout_ValidHours(t *testing.T) {
	duration, err := parseJwtTokenTimeout("8h")
	assert.NoError(t, err)
	assert.Equal(t, 8*time.Hour, duration)
}

// TestParseJwtTokenTimeout_ValidDays tests parsing valid days format
func TestParseJwtTokenTimeout_ValidDays(t *testing.T) {
	duration, err := parseJwtTokenTimeout("7d")
	assert.NoError(t, err)
	assert.Equal(t, 7*24*time.Hour, duration)
}

// TestParseJwtTokenTimeout_MaxDays tests parsing maximum allowed days (30d)
func TestParseJwtTokenTimeout_MaxDays(t *testing.T) {
	duration, err := parseJwtTokenTimeout("30d")
	assert.NoError(t, err)
	assert.Equal(t, 30*24*time.Hour, duration)
}

// TestParseJwtTokenTimeout_ExceedsMaxDays tests that timeout exceeding 30 days is rejected
func TestParseJwtTokenTimeout_ExceedsMaxDays(t *testing.T) {
	_, err := parseJwtTokenTimeout("31d")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds maximum allowed duration of 30 days")
}

// TestParseJwtTokenTimeout_InvalidFormat tests invalid timeout format
func TestParseJwtTokenTimeout_InvalidFormat(t *testing.T) {
	testCases := []string{
		"30",      // Missing unit
		"30x",     // Invalid unit
		"m30",     // Wrong order
		"30 m",    // Space in format
		"",        // Empty string
		"invalid", // Non-numeric
		"30mm",    // Double unit
	}

	for _, tc := range testCases {
		_, err := parseJwtTokenTimeout(tc)
		assert.Error(t, err, "Expected error for format: %s", tc)
	}
}

// TestParseJwtTokenTimeout_WithWhitespace tests parsing with leading/trailing whitespace
func TestParseJwtTokenTimeout_WithWhitespace(t *testing.T) {
	duration, err := parseJwtTokenTimeout("  15m  ")
	assert.NoError(t, err)
	assert.Equal(t, 15*time.Minute, duration)
}

// TestParseJwtTokenTimeout_VariousFormats tests various timeout formats
func TestParseJwtTokenTimeout_VariousFormats(t *testing.T) {
	tests := []struct {
		name     string
		timeout  string
		expected time.Duration
		wantErr  bool
	}{
		{"1 minute", "1m", 1 * time.Minute, false},
		{"60 minutes", "60m", 60 * time.Minute, false},
		{"1 hour", "1h", 1 * time.Hour, false},
		{"24 hours", "24h", 24 * time.Hour, false},
		{"1 day", "1d", 24 * time.Hour, false},
		{"7 days", "7d", 7 * 24 * time.Hour, false},
		{"30 days (max)", "30d", 30 * 24 * time.Hour, false},
		{"31 days (exceeds max)", "31d", 0, true},
		{"invalid", "invalid", 0, true},
		{"empty", "", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			duration, err := parseJwtTokenTimeout(tt.timeout)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, duration)
			}
		})
	}
}

// TestValidateUsername tests username validation
func TestValidateUsername(t *testing.T) {
	cfg := &config.ConfigFile{
		Rbac: config.ConfigFileRbac{
			Users: map[string]config.ConfigFileRbacUsers{
				"valid_user": {Role: "admin"},
				"user-123":   {Role: "guest"},
				"alice_bob":  {Role: "admin"},
			},
		},
	}

	logger := zerolog.New(os.Stderr)
	auth := New(cfg, logger, []byte("secret"))

	tests := []struct {
		name     string
		username string
		wantErr  bool
		errMsg   string
	}{
		{
			name:     "Success: Valid username",
			username: "valid_user",
			wantErr:  false,
		},
		{
			name:     "Success: Valid username with dash",
			username: "user-123",
			wantErr:  false,
		},
		{
			name:     "Success: Valid username with underscore",
			username: "alice_bob",
			wantErr:  false,
		},
		{
			name:     "Error: Empty username",
			username: "",
			wantErr:  true,
			errMsg:   "username cannot be empty",
		},
		{
			name:     "Error: Username too long",
			username: string(make([]byte, 256)),
			wantErr:  true,
			errMsg:   "username too long",
		},
		{
			name:     "Error: Invalid characters (space)",
			username: "invalid user",
			wantErr:  true,
			errMsg:   "username contains invalid characters",
		},
		{
			name:     "Error: Invalid characters (special)",
			username: "user@domain",
			wantErr:  true,
			errMsg:   "username contains invalid characters",
		},
		{
			name:     "Error: User not found",
			username: "nonexistent",
			wantErr:  true,
			errMsg:   "user \"nonexistent\" not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := auth.validateUsername(tt.username)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestValidateUserPermissions tests permission validation
func TestValidateUserPermissions(t *testing.T) {
	cfg := &config.ConfigFile{
		Rbac: config.ConfigFileRbac{
			Roles: map[string]config.ConfigFileRbacRoles{
				"admin": {Permissions: []string{"read", "write", "delete"}},
				"guest": {Permissions: []string{"read"}},
			},
			Users: map[string]config.ConfigFileRbacUsers{
				"alice":   {Role: "admin"},
				"bob":     {Role: "guest"},
				"charlie": {Role: "non_existent_role"},
			},
		},
	}

	logger := zerolog.New(os.Stderr)
	auth := New(cfg, logger, []byte("secret"))

	tests := []struct {
		name       string
		username   string
		permission string
		wantErr    bool
		errMsg     string
	}{
		{
			name:       "Success: Admin can write",
			username:   "alice",
			permission: "write",
			wantErr:    false,
		},
		{
			name:       "Success: Guest can read",
			username:   "bob",
			permission: "read",
			wantErr:    false,
		},
		{
			name:       "Error: User not found",
			username:   "unknown",
			permission: "read",
			wantErr:    true,
			errMsg:     "not found",
		},
		{
			name:       "Error: Role does not exist",
			username:   "charlie",
			permission: "read",
			wantErr:    true,
			errMsg:     "does not exists",
		},
		{
			name:       "Error: Missing permission",
			username:   "bob",
			permission: "delete",
			wantErr:    true,
			errMsg:     "does not have the permission",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := auth.validateUserPermissions(tt.username, tt.permission)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestCheckUserAndPassword tests user and password validation
func TestCheckUserAndPassword(t *testing.T) {
	hashPasswordSHA256 := func(pw string) string {
		sum := sha256.Sum256([]byte(pw))
		return hex.EncodeToString(sum[:])
	}

	hashPasswordBcrypt := func(pw string) string {
		hash, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
		if err != nil {
			t.Fatalf("Failed to generate bcrypt hash: %v", err)
		}
		return string(hash)
	}

	validUser := "alice"
	validPass := "secret123"
	bcryptUser := "bob"
	bcryptPass := "bcrypt_password"

	cfg := &config.ConfigFile{
		Rbac: config.ConfigFileRbac{
			Users: map[string]config.ConfigFileRbacUsers{
				validUser:  {Password: hashPasswordSHA256(validPass)},
				bcryptUser: {Password: hashPasswordBcrypt(bcryptPass)},
			},
		},
	}

	logger := zerolog.New(os.Stderr)
	auth := New(cfg, logger, []byte("secret"))

	tests := []struct {
		name     string
		username string
		password string
		wantErr  bool
		errMsg   string
	}{
		{
			name:     "Success: Correct SHA256 Password",
			username: validUser,
			password: validPass,
			wantErr:  false,
		},
		{
			name:     "Success: Correct bcrypt Password",
			username: bcryptUser,
			password: bcryptPass,
			wantErr:  false,
		},
		{
			name:     "Error: Wrong Password",
			username: validUser,
			password: "wrong-password",
			wantErr:  true,
			errMsg:   "password not correct",
		},
		{
			name:     "Error: User not found",
			username: "unknown",
			password: "any",
			wantErr:  true,
			errMsg:   "not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := auth.checkUserAndPassword(tt.username, tt.password)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
