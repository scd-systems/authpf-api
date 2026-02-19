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
