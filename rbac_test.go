package main

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestValidateUserPermissions(t *testing.T) {
	cfg := &ConfigFile{
		Rbac: ConfigFileRbac{
			Roles: map[string]ConfigFileRbacRoles{
				"admin": {Permissions: []string{"read", "write", "delete"}},
				"guest": {Permissions: []string{"read"}},
			},
			Users: map[string]ConfigFileRbacUsers{
				"alice":   {Role: "admin"},
				"bob":     {Role: "guest"},
				"charlie": {Role: "non_existent_role"},
			},
		},
	}

	tests := []struct {
		name       string
		username   string
		permission string
		wantErr    bool
		expected   string
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
			expected:   "User \"unknown\" not found",
		},
		{
			name:       "Error: Role does not exist",
			username:   "charlie",
			permission: "read",
			wantErr:    true,
			expected:   "Role \"non_existent_role\" for user \"charlie\" does not exists",
		},
		{
			name:       "Error: Missing permission",
			username:   "bob",
			permission: "delete",
			wantErr:    true,
			expected:   "User \"bob\" does not have the permission [\"delete\"] (Role: guest)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := cfg.validateUserPermissions(tt.username, tt.permission)

			if (err != nil) != tt.wantErr {
				t.Errorf("validateUserPermissions() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				if err.Error() != tt.expected {
					t.Errorf("validateUserPermissions() error message = %q, want %q", err.Error(), tt.expected)
				}
			}
		})
	}
}

func TestCheckUserAndPassword(t *testing.T) {
	// Helper function to create a valid password hash in hex format (SHA256)
	hashPasswordSHA256 := func(pw string) string {
		sum := sha256.Sum256([]byte(pw))
		return hex.EncodeToString(sum[:])
	}

	// Helper function to create a bcrypt hash
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

	cfg := &ConfigFile{
		Rbac: ConfigFileRbac{
			Users: map[string]ConfigFileRbacUsers{
				validUser:  {Password: hashPasswordSHA256(validPass)},
				bcryptUser: {Password: hashPasswordBcrypt(bcryptPass)},
				"charlie":  {Password: "invalid-hex-string-!!"},
			},
		},
	}

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
			name:     "Error: Wrong bcrypt Password",
			username: bcryptUser,
			password: "wrong-password",
			wantErr:  true,
			errMsg:   "password not correct",
		},
		{
			name:     "Error: User not found",
			username: "unknown",
			password: "any",
			wantErr:  true,
			errMsg:   "user \"unknown\" not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := cfg.checkUserAndPassword(tt.username, tt.password)

			if (err != nil) != tt.wantErr {
				t.Errorf("checkUserAndPassword() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr && err.Error() != tt.errMsg {
				t.Errorf("checkUserAndPassword() error = %q, wantMsg %q", err.Error(), tt.errMsg)
			}
		})
	}
}

func TestValidateUsername(t *testing.T) {
	cfg := &ConfigFile{
		Rbac: ConfigFileRbac{
			Users: map[string]ConfigFileRbacUsers{
				"valid_user": {Role: "admin"},
				"user-123":   {Role: "guest"},
				"alice_bob":  {Role: "admin"},
			},
		},
	}

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
			errMsg:   "username too long (max 255 characters)",
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
			err := cfg.validateUsername(tt.username)

			if (err != nil) != tt.wantErr {
				t.Errorf("validateUsername() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr && err.Error() != tt.errMsg {
				t.Errorf("validateUsername() error = %q, wantMsg %q", err.Error(), tt.errMsg)
			}
		})
	}
}

func TestGeneratePasswordHash(t *testing.T) {
	tests := []struct {
		name     string
		password string
		wantErr  bool
	}{
		{
			name:     "Success: Generate hash for simple password",
			password: "mypassword123",
			wantErr:  false,
		},
		{
			name:     "Success: Generate hash for complex password",
			password: "P@ssw0rd!#$%^&*()",
			wantErr:  false,
		},
		{
			name:     "Success: Generate hash for empty password",
			password: "",
			wantErr:  false,
		},
		{
			name:     "Success: Generate hash for long password (max 72 bytes)",
			password: "this_is_a_very_long_password_with_many_characters_and_special_symbols",
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash, err := GeneratePasswordHash(tt.password)

			if (err != nil) != tt.wantErr {
				t.Errorf("GeneratePasswordHash() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				// Verify hash is not empty
				if hash == "" {
					t.Errorf("GeneratePasswordHash() returned empty hash")
				}

				// Verify hash is a bcrypt hash (starts with $2a$, $2b$, or $2y$)
				if len(hash) < 4 || (hash[:4] != "$2a$" && hash[:4] != "$2b$" && hash[:4] != "$2y$") {
					t.Errorf("GeneratePasswordHash() returned invalid bcrypt hash format: %s", hash)
				}

				// Verify the hash is valid by comparing it with the SHA256 hex string of the password
				// GeneratePasswordHash creates SHA256(password) and then bcrypt(hex(SHA256(password)))
				sha256Hash := sha256.Sum256([]byte(tt.password))
				sha256HexString := hex.EncodeToString(sha256Hash[:])
				err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(sha256HexString))
				if err != nil {
					t.Errorf("GeneratePasswordHash() produced invalid hash: %v", err)
				}
			}
		})
	}
}

func TestCheckUserAndPasswordSHA256Fallback(t *testing.T) {
	// Helper function to create a valid password hash in hex format (SHA256)
	hashPasswordSHA256 := func(pw string) string {
		sum := sha256.Sum256([]byte(pw))
		return hex.EncodeToString(sum[:])
	}

	validUser := "alice"
	validPass := "legacy_password"

	cfg := &ConfigFile{
		Rbac: ConfigFileRbac{
			Users: map[string]ConfigFileRbacUsers{
				validUser: {Password: hashPasswordSHA256(validPass)},
			},
		},
	}

	tests := []struct {
		name     string
		username string
		password string
		wantErr  bool
	}{
		{
			name:     "Success: SHA256 fallback with correct password",
			username: validUser,
			password: validPass,
			wantErr:  false,
		},
		{
			name:     "Error: SHA256 fallback with wrong password",
			username: validUser,
			password: "wrong_password",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := cfg.checkUserAndPassword(tt.username, tt.password)

			if (err != nil) != tt.wantErr {
				t.Errorf("checkUserAndPassword() SHA256 fallback error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
