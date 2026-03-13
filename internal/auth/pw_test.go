package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/bcrypt"
)

// TestGeneratePasswordHash_Consistency tests that same password generates different hashes
func TestGeneratePasswordHash_Consistency(t *testing.T) {
	password := "testpassword123"

	hash1, err1 := GeneratePasswordHash(password)
	assert.NoError(t, err1)

	hash2, err2 := GeneratePasswordHash(password)
	assert.NoError(t, err2)

	// Hashes should be different (bcrypt uses salt)
	assert.NotEqual(t, hash1, hash2)

	// But both should be valid bcrypt hashes
	sha256Hash := sha256.Sum256([]byte(password))
	sha256HexString := hex.EncodeToString(sha256Hash[:])

	err := bcrypt.CompareHashAndPassword([]byte(hash1), []byte(sha256HexString))
	assert.NoError(t, err)

	err = bcrypt.CompareHashAndPassword([]byte(hash2), []byte(sha256HexString))
	assert.NoError(t, err)
}

// TestGeneratePasswordHash tests password hash generation
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
			name:     "Success: Generate hash for long password",
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
				assert.NotEmpty(t, hash)

				// Verify hash is a bcrypt hash (starts with $2a$, $2b$, or $2y$)
				assert.True(t, len(hash) >= 4 && (hash[:4] == "$2a$" || hash[:4] == "$2b$" || hash[:4] == "$2y$"),
					"Expected valid bcrypt hash format, got: %s", hash)

				// Verify the hash is valid by comparing it with the SHA256 hex string of the password
				sha256Hash := sha256.Sum256([]byte(tt.password))
				sha256HexString := hex.EncodeToString(sha256Hash[:])
				err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(sha256HexString))
				assert.NoError(t, err, "Generated hash should be valid")
			}
		})
	}
}
