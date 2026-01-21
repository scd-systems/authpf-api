package main

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
)

// activateAuthPFRule handles POST /api/v1/authpf/activate
func activateAuthPFRule(c echo.Context) error {
	lock.Lock()
	defer lock.Unlock()

	// Build and validate the AuthPFRule
	r, valErr := SetAuthPFRule(c, SESSION_REGISTER)
	if valErr != nil {
		return RespondWithValidationError(c, valErr)
	}

	// Perform additional activation-specific validations
	if valErr := ValidateAuthPFRule(r, SESSION_REGISTER); valErr != nil {
		return RespondWithValidationErrorStatus(c, valErr)
	}

	// Run pfctl command
	result := loadAuthPFRule(r)
	msg := fmt.Sprintf("Exec: '%s %s', ExitCode: %d, Stdout: %s, StdErr: %s", result.Command, strings.Join(result.Args, " "), result.ExitCode, result.Stdout, result.Stderr)
	logger.Trace().Str("user", c.Get("username").(string)).Msg(msg)

	if result.Error != nil {
		msg := "Loading authpf rules failed"
		c.Set("authpf", result.Stderr)
		return c.JSON(http.StatusInternalServerError, echo.Map{"status": "failed", "message": msg})
	}

	// Store status into DB
	if err := addToRulesDB(r); err != nil {
		msg := "Unable to store user into Session DB"
		c.Set("authpf", msg)
		return c.JSON(http.StatusInternalServerError, echo.Map{"status": "failed", "message": msg})
	}

	c.Set("authpf", fmt.Sprintf("Activated authpf rule: user=%s, user_ip=%s, user_id=%d, timeout=%s, expire_at=%s", r.Username, r.UserIP, r.UserID, r.Timeout, r.ExpiresAt))
	return c.JSON(http.StatusCreated, echo.Map{"status": "activated", "user": r.Username, "message": "authpf rule is being loaded"})
}

// getLoadAuthPFRules handles GET /api/v1/authpf/activate
func getLoadAuthPFRules(c echo.Context) error {
	lock.Lock()
	defer lock.Unlock()

	// Get and validate session username
	username, valErr := ValidateSessionUsername(c)
	if valErr != nil {
		return RespondWithValidationError(c, valErr)
	}

	// Get optional authpf_username parameter
	requestedUser := c.QueryParam("authpf_username")

	// Resolve target user with proper validation and permission checks
	reqUser, valErr := ResolveTargetUser(c, username, requestedUser, RBAC_GET_STATUS_OTHER_RULE)
	if valErr != nil {
		return RespondWithValidationErrorStatus(c, valErr)
	}

	response := &AuthPFRulesResponse{
		Rules:      map[string]*AuthPFRule{reqUser: anchorsDB[reqUser]},
		ServerTime: time.Now().UTC(),
	}
	return c.JSON(http.StatusOK, response)
}

// getAllLoadAuthPFRules handles GET /api/v1/authpf/all
func getAllLoadAuthPFRules(c echo.Context) error {
	lock.Lock()
	defer lock.Unlock()

	// Get and validate session username
	username, valErr := ValidateSessionUsername(c)
	if valErr != nil {
		return RespondWithValidationError(c, valErr)
	}

	// Check permission to view all rules
	if valErr := CheckPermission(username, RBAC_GET_STATUS_OTHER_RULE); valErr != nil {
		return RespondWithValidationErrorStatus(c, valErr)
	}

	response := &AuthPFRulesResponse{
		Rules:      anchorsDB,
		ServerTime: time.Now().UTC(),
	}
	return c.JSON(http.StatusOK, response)
}

// deactivateAuthPFRule handles DELETE /api/v1/authpf/activate
func deactivateAuthPFRule(c echo.Context) error {
	lock.Lock()
	defer lock.Unlock()

	// Build and validate the AuthPFRule
	r, valErr := SetAuthPFRule(c, SESSION_UNREGISTER)
	if valErr != nil {
		return RespondWithValidationError(c, valErr)
	}

	// Perform additional deactivation-specific validations
	if valErr := ValidateAuthPFRule(r, SESSION_UNREGISTER); valErr != nil {
		return RespondWithValidationErrorStatus(c, valErr)
	}

	multiResult := unloadAuthPFRule(r)

	// Log all commands
	for i, result := range multiResult.Results {
		msg := fmt.Sprintf("Exec [%d/%d]: '%s %s', ExitCode: %d, Stdout: %s, StdErr: %s",
			i+1, len(multiResult.Results), result.Command, strings.Join(result.Args, " "),
			result.ExitCode, result.Stdout, result.Stderr)
		logger.Debug().Str("user", r.Username).Msg(msg)
	}

	if multiResult.Error != nil {
		msg := "unload authpf rules failed"
		c.Set("authpf", msg)
		return c.JSON(http.StatusInternalServerError, echo.Map{"status": "failed", "message": msg})
	}

	// Remove User from db
	if err := removeFromRulesDB(r.Username, r.UserIP); err != nil {
		msg := "Unable to remove user from Session DB"
		c.Set("authpf", msg)
		return c.JSON(http.StatusInternalServerError, echo.Map{"status": "failed", "message": msg})
	}

	msg := "authpf rule is being unloaded"
	c.Set("authpf", msg)
	return c.JSON(http.StatusAccepted, echo.Map{"status": "queued", "user": r.Username, "message": msg})
}

// Run Load AuthPF Rule
func loadAuthPFRule(r *AuthPFRule) *SystemCommandResult {
	parameters := buildPfctlActivateCmdParameters(r)
	return executePfctlCommand(parameters)
}

// Run Unload AuthPF Rule
func unloadAuthPFRule(r *AuthPFRule) *MultiCommandResult {
	parameters := buildPfctlDeactivateCmdParameters(r)
	return executePfctlCommands(parameters)
}

// Run Unload ALL AuthPF Rules
func unloadAllAuthPFRule() *MultiCommandResult {
	parameters := buildPfctlDeactivateAllCmdParameters()
	return executePfctlCommands(parameters)
}

// deleteAllAuthPFRules handles DELETE /api/v1/authpf/all
func deactivateAllAuthPFRules(c echo.Context) error {
	lock.Lock()
	defer lock.Unlock()

	// Get and validate session username
	username, valErr := ValidateSessionUsername(c)
	if valErr != nil {
		return RespondWithValidationError(c, valErr)
	}

	// Check permission to deactivate all rules
	if valErr := CheckPermission(username, RBAC_DEACTIVATE_OTHER_RULE); valErr != nil {
		return RespondWithValidationErrorStatus(c, valErr)
	}

	if err := execUnloadAllAuthPFRules(username); err != nil {
		msg := "unload all authpf rules failed"
		c.Set("authpf", msg)
		return c.JSON(http.StatusInternalServerError, echo.Map{"status": "failed", "message": msg})
	}

	return c.JSON(http.StatusOK, echo.Map{"status": "cleared"})
}

func execUnloadAllAuthPFRules(username string) error {
	if len(anchorsDB) < 1 {
		logger.Debug().Msg("No anchors to flush")
		return nil
	}

	msg := fmt.Sprintf("Found %d user anchors to flush", len(anchorsDB))
	logger.Debug().Msg(msg)
	multiResult := unloadAllAuthPFRule()

	// Log all commands
	for i, result := range multiResult.Results {
		msg := fmt.Sprintf("Exec [%d/%d]: '%s %s', ExitCode: %d, Stdout: %s, StdErr: %s",
			i+1, len(multiResult.Results), result.Command, strings.Join(result.Args, " "),
			result.ExitCode, result.Stdout, result.Stderr)
		logger.Debug().Str("user", username).Msg(msg)
	}

	if multiResult.Error != nil {
		msg := fmt.Sprintf("unload all authpf rules failed: %s", multiResult.Error)
		logger.Debug().Str("user", username).Msg(msg)
		return multiResult.Error
	}
	anchorsDB = make(map[string]*AuthPFRule)
	logger.Debug().Msg("Flushing anchors succeed")
	return nil
}

func addToRulesDB(r *AuthPFRule) error {
	anchorsDB[r.Username] = r
	return nil
}

func removeFromRulesDB(username string, user_ip string) error {
	for idx, v := range anchorsDB {
		if v.Username == username {
			delete(anchorsDB, idx)
		}
	}
	return nil
}
