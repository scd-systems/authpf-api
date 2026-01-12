package main

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/rs/zerolog"
)

// loadAuthPFRule handles POST /api/v1/authpf/activate
func activateAuthPFRule(c echo.Context) error {
	lock.Lock()
	defer lock.Unlock()
	logger := c.Get("logger").(zerolog.Logger)

	r := &AuthPFRule{}

	// Get and validate session username
	username, valErr := ValidateSessionUsername(c)
	if valErr != nil {
		return RespondWithValidationError(c, valErr)
	}
	r.Username = username

	if valErr := ValidateUserIP(c.RealIP()); valErr != nil {
		return RespondWithValidationErrorStatus(c, valErr)
	}
	r.UserIP = c.RealIP()

	// Get query parameters
	reqTimeout := c.QueryParam("timeout")
	reqUser := c.QueryParam("authpf_username")

	// Validate and resolve target user
	targetUser, valErr := ResolveTargetUser(c, username, reqUser, RBAC_ACTIVATE_OTHER_RULE, logger)
	if valErr != nil {
		return RespondWithValidationErrorStatus(c, valErr)
	}
	r.Username = targetUser

	// Validate timeout
	timeout, expiresAt, valErr := ValidateTimeout(reqTimeout)
	if valErr != nil {
		return RespondWithValidationError(c, valErr)
	}
	r.Timeout = timeout
	r.ExpiresAt = expiresAt

	// Validate payload
	if valErr := ValidatePayload(c, r); valErr != nil {
		return RespondWithValidationError(c, valErr)
	}

	// Set UserID if available
	SetUserID(r)

	// Check if session already exists
	if valErr := CheckSessionExists(r, logger, "activate"); valErr != nil {
		return RespondWithValidationError(c, valErr)
	}

	// Check permission to activate own rules
	if valErr := CheckPermission(r.Username, RBAC_ACTIVATE_OWN_RULE, logger); valErr != nil {
		return RespondWithValidationErrorStatus(c, valErr)
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

	// Store status into DB
	if err := addToRulesDB(r); err != nil {
		msg := "Unable to store user into Session DB"
		logger.Info().Str("status", "failed").Str("user", r.Username).Msg(msg)
		return c.JSON(http.StatusInternalServerError, echo.Map{"status": "failed", "message": msg})
	}

	msg = fmt.Sprintf("Loading authpf rule: user=%s, user_ip=%s, user_id=%d, timeout=%s, expire_at=%s", r.Username, r.UserIP, r.UserID, r.Timeout, r.ExpiresAt)
	logger.Info().Str("status", "activated").Str("user", r.Username).Msg(msg)
	return c.JSON(http.StatusCreated, echo.Map{"status": "activated", "user": r.Username, "message": "authpf rule is being loaded"})
}

// getLoadAuthPFRules handles GET /api/v1/authpf/activate
func getLoadAuthPFRules(c echo.Context) error {
	lock.Lock()
	defer lock.Unlock()
	logger := c.Get("logger").(zerolog.Logger)

	// Get and validate session username
	username, valErr := ValidateSessionUsername(c)
	if valErr != nil {
		return RespondWithValidationError(c, valErr)
	}

	// Check permission to view own rules
	if valErr := CheckPermission(username, RBAC_GET_STATUS_OWN_RULE, logger); valErr != nil {
		return RespondWithValidationErrorStatus(c, valErr)
	}

	response := &AuthPFRulesResponse{
		Rules:      map[string]*AuthPFRule{username: rulesdb[username]},
		ServerTime: time.Now().UTC(),
	}
	return c.JSON(http.StatusOK, response)
}

// getAllLoadAuthPFRules handles GET /api/v1/authpf/all
func getAllLoadAuthPFRules(c echo.Context) error {
	lock.Lock()
	defer lock.Unlock()
	logger := c.Get("logger").(zerolog.Logger)

	// Get and validate session username
	username, valErr := ValidateSessionUsername(c)
	if valErr != nil {
		return RespondWithValidationError(c, valErr)
	}

	// Check permission to view all rules
	if valErr := CheckPermission(username, RBAC_GET_STATUS_OTHER_RULE, logger); valErr != nil {
		return RespondWithValidationErrorStatus(c, valErr)
	}

	response := &AuthPFRulesResponse{
		Rules:      rulesdb,
		ServerTime: time.Now().UTC(),
	}
	return c.JSON(http.StatusOK, response)
}

// deleteOwnAuthPFRules handles DELETE /api/v1/authpf/activate
func deactivateAuthPFRule(c echo.Context) error {
	lock.Lock()
	defer lock.Unlock()
	logger := c.Get("logger").(zerolog.Logger)

	r := &AuthPFRule{}

	// Get and validate session username
	username, valErr := ValidateSessionUsername(c)
	if valErr != nil {
		return RespondWithValidationError(c, valErr)
	}
	r.Username = username
	r.UserIP = c.RealIP()

	// Get query parameters
	reqUser := c.QueryParam("authpf_username")

	// Validate payload
	if valErr := ValidatePayload(c, r); valErr != nil {
		return RespondWithValidationError(c, valErr)
	}

	// Validate and resolve target user
	targetUser, valErr := ResolveTargetUser(c, username, reqUser, RBAC_DEACTIVATE_OTHER_RULE, logger)
	if valErr != nil {
		return RespondWithValidationErrorStatus(c, valErr)
	}
	r.Username = targetUser

	// Check if session exists
	if valErr := CheckSessionExists(r, logger, "deactivate"); valErr != nil {
		return RespondWithValidationError(c, valErr)
	}

	// Check permission to deactivate own rules
	if valErr := CheckPermission(r.Username, RBAC_DEACTIVATE_OWN_RULE, logger); valErr != nil {
		return RespondWithValidationErrorStatus(c, valErr)
	}

	multiResult := unloadAuthPFRule(r.Username)

	// Log all commands
	for i, result := range multiResult.Results {
		msg := fmt.Sprintf("Exec [%d/%d]: '%s %s', ExitCode: %d, Stdout: %s, StdErr: %s",
			i+1, len(multiResult.Results), result.Command, strings.Join(result.Args, " "),
			result.ExitCode, result.Stdout, result.Stderr)
		logger.Debug().Str("user", r.Username).Msg(msg)
	}

	if multiResult.Error != nil {
		msg := "authpf rule not unloaded"
		logger.Info().Str("user", r.Username).Msg(msg)
		return c.JSON(http.StatusInternalServerError, echo.Map{"status": "failed", "message": msg})
	}

	// Remove User from db
	if err := removeFromRulesDB(r.Username, r.UserIP); err != nil {
		msg := "Unable to remove user from Session DB"
		logger.Info().Str("status", "failed").Str("user", r.Username).Msg(msg)
		return c.JSON(http.StatusInternalServerError, echo.Map{"status": "failed", "message": msg})
	}

	msg := "authpf rule is being unloaded"
	logger.Info().Str("status", "queued").Str("user", r.Username).Msg(msg)
	return c.JSON(http.StatusAccepted, echo.Map{"status": "queued", "user": r.Username, "message": msg})
}

// Run Load AuthPF Rule
func loadAuthPFRule(r *AuthPFRule) *SystemCommandResult {
	parameters := buildPfctlActivateCmdParameters(r)
	return executePfctlCommand(parameters)
}

// Run Unload AuthPF Rule
func unloadAuthPFRule(username string) *MultiCommandResult {
	r := &AuthPFRule{
		Username: username,
	}
	parameters := buildPfctlDeactivateCmdParameters(r)
	return executePfctlCommands(parameters)
}

// deleteAllAuthPFRules handles DELETE /api/v1/authpf/all
func deactivateAllAuthPFRules(c echo.Context) error {
	lock.Lock()
	defer lock.Unlock()
	logger := c.Get("logger").(zerolog.Logger)

	// Get and validate session username
	username, valErr := ValidateSessionUsername(c)
	if valErr != nil {
		return RespondWithValidationError(c, valErr)
	}

	// Check permission to deactivate all rules
	if valErr := CheckPermission(username, RBAC_DEACTIVATE_OTHER_RULE, logger); valErr != nil {
		return RespondWithValidationErrorStatus(c, valErr)
	}

	//TODO: pfctl -a "authpf/*" -Fa
	rulesdb = make(map[string]*AuthPFRule)
	return c.JSON(http.StatusOK, echo.Map{"status": "cleared"})
}

func addToRulesDB(r *AuthPFRule) error {
	rulesdb[r.Username] = r
	return nil
}

func removeFromRulesDB(username string, user_ip string) error {
	for idx, v := range rulesdb {
		if v.Username == username {
			delete(rulesdb, idx)
		}
	}
	return nil
}
