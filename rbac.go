package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"log"
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
	_, ok := c.Rbac.Users[username]
	if !ok {
		return fmt.Errorf("User %q not found", username)
	}
	userPassword, err := hex.DecodeString(c.Rbac.Users[username].Password)
	if err != nil {
		log.Fatal(err)
	}
	requestPassword := sha256.Sum256([]byte(clearTextPassword))
	if ret := subtle.ConstantTimeCompare(requestPassword[:], userPassword); ret != 1 {
		return fmt.Errorf("Password not correct")
	}
	return nil
}
