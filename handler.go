package main

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/rs/zerolog"
)

// validatePayload validates the JSON payload from the request
func validatePayload(c echo.Context, r *AuthPFRule) error {
	if err := c.Bind(r); err != nil {
		return c.JSON(http.StatusBadRequest, echo.Map{"error": "invalid JSON payload"})
	}
	return nil
}

// getSessionUsername validates the username from the JWT token in the Echo context
// Returns the username if valid, or an error if validation fails
func getSessionUsername(c echo.Context) (string, error) {
	username, ok := c.Get("username").(string)
	if !ok || username == "" {
		return "", c.JSON(http.StatusUnauthorized, echo.Map{"error": "invalid username in token"})
	}
	return username, nil
}

// loadAuthPFRule handles POST /api/v1/authpf/activate
func activateAuthPFRule(c echo.Context) error {
	lock.Lock()
	defer lock.Unlock()
	logger := c.Get("logger").(zerolog.Logger)

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

	if err := validatePayload(c, r); err != nil {
		return err
	}

	r.ClientIP = c.RealIP()

	username, err := getSessionUsername(c)
	if err != nil {
		return err
	}

	r.Username = username
	if config.Rbac.Users[r.Username].ClientID > 0 {
		r.ClientID = config.Rbac.Users[r.Username].ClientID
	}

	for _, v := range rulesdb {
		if v.Username == r.Username {
			msg := "authpf rule for user already activated"
			logger.Info().Str("user", r.Username).Msg(msg)
			return c.JSON(http.StatusMethodNotAllowed, echo.Map{"error": msg})
		}
	}

	rulesdb[r.Username] = r

	// Check permission
	if err := config.validateUserPermissions(r.Username, RBAC_ACTIVATE_RULE); err != nil {
		logger.Info().Str("status", "rejected").Str("user", r.Username).Msg(err.Error())
		return c.JSON(http.StatusForbidden, echo.Map{"status": "rejected", "message": err.Error()})
	}

	// Run pfctl command
	result := loadAuthPFRule(r)
	msg := fmt.Sprintf("Exec: '%s %s', ExitCode: %d, Stdout: %s, StdErr: %s", result.Command, strings.Join(result.Args, " "), result.ExitCode, result.Stdout, result.Stderr)
	logger.Debug().Str("user", r.Username).Msg(msg)

	if result.Error != nil {
		msg := "Loading authpf rules failed"
		logger.Info().Str("status", "failed").Str("user", r.Username).Msg(msg)
		return c.JSON(http.StatusInternalServerError, echo.Map{"status": "failed", "message": msg})
	}

	msg = fmt.Sprintf("Loading authpf rule: user=%s, client_ip=%s, client_id=%d, timeout=%s, expire_at=%s", r.Username, r.ClientIP, r.ClientID, r.Timeout, r.ExpiresAt)
	logger.Info().Str("status", "activated").Str("user", r.Username).Msg(msg)
	return c.JSON(http.StatusCreated, echo.Map{"status": "activated", "user": r.Username, "message": "authpf rule is being loaded"})
}

// getLoadAuthPFRules handles GET /api/v1/authpf/activate
func getLoadAuthPFRules(c echo.Context) error {
	lock.Lock()
	defer lock.Unlock()

	username, err := getSessionUsername(c)
	if err != nil {
		return err
	}

	// Check permission
	if err := config.validateUserPermissions(username, RBAC_GET_STATUS_OWN_RULE); err != nil {
		c.Logger().Infof(err.Error())
		return c.JSON(http.StatusForbidden, echo.Map{"status": "rejected", "message": err.Error()})
	}

	return c.JSON(http.StatusOK, rulesdb[username])
}

// getAllLoadAuthPFRules handles GET /api/v1/authpf/all
func getAllLoadAuthPFRules(c echo.Context) error {
	lock.Lock()
	defer lock.Unlock()

	username, err := getSessionUsername(c)
	if err != nil {
		return err
	}

	// Check permission
	if err := config.validateUserPermissions(username, RBAC_GET_STATUS_OTHER_RULE); err != nil {
		c.Logger().Infof(err.Error())
		return c.JSON(http.StatusForbidden, echo.Map{"status": "rejected", "message": err.Error()})
	}
	return c.JSON(http.StatusOK, rulesdb)
}

// deleteOwnAuthPFRules handles DELETE /api/v1/authpf/activate
func deactivateAuthPFRule(c echo.Context) error {
	lock.Lock()
	defer lock.Unlock()
	logger := c.Get("logger").(zerolog.Logger)

	r := &AuthPFRule{}

	if err := validatePayload(c, r); err != nil {
		return err
	}

	r.ClientIP = c.RealIP()
	username, err := getSessionUsername(c)
	if err != nil {
		return err
	}
	r.Username = username

	if _, ok := rulesdb[r.Username]; !ok {
		msg := "authpf rule for user not activated"
		logger.Info().Str("status", "failed").Str("user", r.Username).Msg(msg)
		return c.JSON(http.StatusMethodNotAllowed, echo.Map{"status": "failed", "message": msg})
	}

	// Check permission
	if err := config.validateUserPermissions(r.Username, RBAC_DEACTIVATE_OWN_RULE); err != nil {
		logger.Info().Str("status", "rejected").Str("user", r.Username).Msg(err.Error())
		return c.JSON(http.StatusForbidden, echo.Map{"status": "rejected", "message": err.Error()})
	}

	// Run pfctl command
	result := unloadAuthPFRule(r.Username)
	msg := fmt.Sprintf("Exec: '%s %s', ExitCode: %d, Stdout: %s, StdErr: %s", result.Command, strings.Join(result.Args, " "), result.ExitCode, result.Stdout, result.Stderr)
	logger.Debug().Str("user", r.Username).Msg(msg)
	if result.Error != nil {
		msg := "authpf rule not unloaded"
		logger.Info().Str("user", r.Username).Msg(msg)
		return c.JSON(http.StatusInternalServerError, echo.Map{"status": "failed", "message": msg})
	}
	// Remove User from db
	for idx, v := range rulesdb {
		if v.Username == r.Username {
			delete(rulesdb, idx)
		}
	}

	msg = "authpf rule is being unloaded"
	logger.Info().Str("status", "queued").Str("user", r.Username).Msg(msg)
	return c.JSON(http.StatusAccepted, echo.Map{"status": "queued", "user": r.Username, "message": msg})
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

	username, err := getSessionUsername(c)
	if err != nil {
		return err
	}

	// Check permission
	if err := config.validateUserPermissions(username, RBAC_DEACTIVATE_OTHER_RULE); err != nil {
		c.Logger().Infof(err.Error())
		return c.JSON(http.StatusForbidden, echo.Map{"status": "rejected", "message": err.Error()})
	}

	//TODO: pfctl -a "authpf/*" -Fa
	rulesdb = make(map[string]*AuthPFRule)
	return c.JSON(http.StatusOK, echo.Map{"status": "cleared"})
}
