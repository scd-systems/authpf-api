package auth

import (
	"crypto/sha256"
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

func GeneratePasswordHash(clearTextPassword string) (string, error) {
	sha256Hash := sha256.Sum256([]byte(clearTextPassword))

	if len(sha256Hash) != 32 {
		return "", fmt.Errorf("something went wrong during password generation")
	}
	pwHash := fmt.Sprintf("%x", sha256Hash)

	hash, err := bcrypt.GenerateFromPassword([]byte(pwHash), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}
