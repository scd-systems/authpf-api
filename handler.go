package main

import (
	"net/http"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
)

// loadAuthPFRule handles POST /api/v1/authpf/activate
func activateAuthPFRule(c echo.Context) error {
	lock.Lock()
	defer lock.Unlock()

	timeoutStr := c.QueryParam("timeout")
	if timeoutStr == "" {
		timeoutStr = config.Defaults.Timeout
	}

	r := &AuthPFRule{
		Timeout: timeoutStr,
	}

	if timeoutStr != "" {
		if d, err := time.ParseDuration(timeoutStr); err == nil {
			r.ExpiresAt = time.Now().Add(d)
		}
	}

	if err := c.Bind(r); err != nil {
		return c.JSON(http.StatusBadRequest, echo.Map{"error": "invalid JSON payload"})
	}

	r.ClientIP = c.RealIP()
	username, ok := c.Get("username").(string)
	if !ok {
		return c.JSON(http.StatusUnauthorized, echo.Map{"error": "invalid username in token"})
	}
	r.Username = username

	for _, v := range rules {
		if v.Username == r.Username {
			c.Logger().Infof("Loading authpf failed")
			return c.JSON(http.StatusMethodNotAllowed, echo.Map{"error": "authpf rule for user already activated"})
		}
	}

	rules[r.Username] = r

	// Check permission
	if err := config.validateUserPermissions(r.Username, RBAC_ACTIVATE_RULE); err != nil {
		c.Logger().Infof(err.Error())
		return c.JSON(http.StatusForbidden, echo.Map{"status": "rejected", "msg": err.Error()})
	}

	// Run pfctl command
	result := loadAuthPFRule(r)
	c.Logger().Debugf("Exec: '%s %s', ExitCode: %d, Stdout: %s, StdErr: %s", result.Command, strings.Join(result.Args, " "), result.ExitCode, result.Stdout, result.Stderr)
	if result.Error != nil {
		c.Logger().Errorf("Loading authpf rules failed for user: %s", r.Username)
		return c.JSON(http.StatusInternalServerError, echo.Map{"status": "failed", "msg": "authpf rule not loaded"})
	}

	c.Logger().Infof("Loading authpf rule user=%s with timeout=%s, ExpireAt=%s", r.Username, r.Timeout, r.ExpiresAt)
	return c.JSON(http.StatusCreated, echo.Map{"status": "activated", "user": r.Username, "msg": "authpf rule is being loaded"})
}

// getLoadAuthPFRules handles GET /api/v1/authpf/rules
func getLoadAuthPFRules(c echo.Context) error {
	lock.Lock()
	defer lock.Unlock()
	return c.JSON(http.StatusOK, rules)
}

// deleteOwnAuthPFRules handles DELETE /api/v1/authpf/activate
func deactivateAuthPFRule(c echo.Context) error {
	lock.Lock()
	defer lock.Unlock()

	r := &AuthPFRule{}

	if err := c.Bind(r); err != nil {
		return c.JSON(http.StatusBadRequest, echo.Map{"error": "invalid JSON payload"})
	}

	r.ClientIP = c.RealIP()
	username, ok := c.Get("username").(string)
	if !ok {
		return c.JSON(http.StatusUnauthorized, echo.Map{"error": "invalid username in token"})
	}

	r.Username = username

	for _, v := range rules {
		if v.Username != r.Username {
			c.Logger().Infof("Unloading authpf failed")
			return c.JSON(http.StatusMethodNotAllowed, echo.Map{"error": "authpf rule for user not activated"})
		}
	}

	// Check permission
	if err := config.validateUserPermissions(r.Username, RBAC_DEACTIVATE_OWN_RULE); err != nil {
		c.Logger().Infof(err.Error())
		return c.JSON(http.StatusForbidden, echo.Map{"status": "rejected", "msg": err.Error()})
	}

	// Run pfctl command
	result := unloadAuthPFRule(r.Username)
	c.Logger().Debugf("Exec: '%s %s', ExitCode: %d, Stdout: %s, StdErr: %s", result.Command, strings.Join(result.Args, " "), result.ExitCode, result.Stdout, result.Stderr)

	if result.Error != nil {
		c.Logger().Errorf("Unloading authpf rules failed for user: %s", r.Username)
		return c.JSON(http.StatusInternalServerError, echo.Map{"status": "failed", "msg": "authpf rule not unloaded"})
	}

	c.Logger().Infof("Unloading authpf rule user=%s succeed", r.Username)
	return c.JSON(http.StatusAccepted, echo.Map{"status": "queued", "user": r.Username, "msg": "authpf rule is being unloaded"})
}

// Run Load AuthPF Rule
func loadAuthPFRule(r *AuthPFRule) *SystemCommandResult {
	parameters := buildPfctlCmdParameters(r, AUTHPF_ACTIVATE)
	return executePfctlCommand(parameters)
}

// Run Unload AuthPF Rule
func unloadAuthPFRule(username string) *SystemCommandResult {
	r := &AuthPFRule{
		Username: username,
	}
	parameters := buildPfctlCmdParameters(r, AUTHPF_DEACTIVATE)
	return executePfctlCommand(parameters)
}

// deleteAllAuthPFRules handles DELETE /api/v1/authpf/all
func deleteAllAuthPFRules(c echo.Context) error {
	lock.Lock()
	defer lock.Unlock()
	rules = make(map[string]*AuthPFRule)
	return c.JSON(http.StatusOK, echo.Map{"status": "cleared"})
}
