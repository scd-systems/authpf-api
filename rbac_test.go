package main

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
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
	// Helper function to create a valid password hash in hex format
	hashPassword := func(pw string) string {
		sum := sha256.Sum256([]byte(pw))
		return hex.EncodeToString(sum[:])
	}

	validUser := "alice"
	validPass := "secret123"

	cfg := &ConfigFile{
		Rbac: ConfigFileRbac{
			Users: map[string]ConfigFileRbacUsers{
				validUser: {Password: hashPassword(validPass)},
				"bob":     {Password: "invalid-hex-string-!!"},
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
			name:     "Success: Correct Password",
			username: validUser,
			password: validPass,
			wantErr:  false,
		},
		{
			name:     "Error: Wrong Password",
			username: validUser,
			password: "wrong-password",
			wantErr:  true,
			errMsg:   "Password not correct",
		},
		{
			name:     "Error: User not found",
			username: "unknown",
			password: "any",
			wantErr:  true,
			errMsg:   "User \"unknown\" not found",
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
