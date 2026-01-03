package main

import "fmt"

func (c *ConfigFile) validateUserPermissions(username string, permission string) error {
	user, ok := c.Rbac.Users[username]
	if !ok {
		return fmt.Errorf("User %q not found", username)
	}

	group, ok := c.Rbac.Groups[user.Group]
	if !ok {
		return fmt.Errorf("Group %q not found", user.Group)
	}

	role, ok := c.Rbac.Roles[group.Role]
	if !ok {
		return fmt.Errorf("Role %q for group %q does not exists", group.Role, user.Group)
	}

	// 4. Über Permissions iterieren und vergleichen
	for _, p := range role.Permissions {
		if p == permission {
			return nil
		}
	}
	return fmt.Errorf("User %q does not have the permission [%q] (Role: %s)", username, permission, group.Role)
}
