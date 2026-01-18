package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"regexp"

	log "github.com/labstack/gommon/log"
	"golang.org/x/crypto/bcrypt"
)

func (c *ConfigFile) validateUserPermissions(username string, permission string) error {
	user, ok := c.Rbac.Users[username]
	if !ok {
		return fmt.Errorf("User %q not found", username)
	}

	role, ok := c.Rbac.Roles[user.Role]
	if !ok {
		return fmt.Errorf("Role %q for user %q does not exists", user.Role, username)
	}

	for _, p := range role.Permissions {
		if p == permission {
			return nil
		}
	}
	return fmt.Errorf("User %q does not have the permission [%q] (Role: %s)", username, permission, user.Role)
}

func (c *ConfigFile) checkUserAndPassword(username string, clearTextPassword string) error {
	user, ok := c.Rbac.Users[username]
	if !ok {
		return fmt.Errorf("user %q not found", username)
	}

	// Use bcrypt
	err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(clearTextPassword))
	if err == nil {
		return nil
	}

	// SHA256 fallback
	if len(user.Password) == 64 {
		userPassword, err := hex.DecodeString(user.Password)
		if err == nil {
			requestPassword := sha256.Sum256([]byte(clearTextPassword))
			if ret := subtle.ConstantTimeCompare(requestPassword[:], userPassword); ret == 1 {
				log.Infof("User %q using legacy SHA256 password - please update to bcrypt", username)
				return nil
			}
		}
	}

	return fmt.Errorf("password not correct")
}

// ValidateUsername check for valid username
func (c *ConfigFile) validateUsername(username string) error {
	if username == "" {
		return fmt.Errorf("username cannot be empty")
	}
	if len(username) > 255 {
		return fmt.Errorf("username too long (max 255 characters)")
	}
	if !regexp.MustCompile(`^[a-zA-Z0-9_-]+$`).MatchString(username) {
		return fmt.Errorf("username contains invalid characters")
	}
	if _, ok := c.Rbac.Users[username]; !ok {
		return fmt.Errorf("user %q not found", username)
	}
	return nil
}

func GeneratePasswordHash(clearTextPassword string) (string, error) {
	sha256Hash := sha256.Sum256([]byte(clearTextPassword))

	if len(sha256Hash) != 32 {
		return "", fmt.Errorf("Something went wrong during password generation")
	}
	pwHash := fmt.Sprintf("%x", sha256Hash)

	hash, err := bcrypt.GenerateFromPassword([]byte(pwHash), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}
