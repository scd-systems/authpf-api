package main

import (
	"github.com/labstack/echo/v4"
)

// SetAuthPFAnchor builds an AuthPFAnchor entry from the request context for either activation or deactivation
// It performs all necessary validations and populates the anchor with required data
// action should be either "activate" or "deactivate"
func SetAuthPFAnchor(c echo.Context, action string) (*AuthPFAnchor, *ValidationError) {
	r := &AuthPFAnchor{}

	// Get and validate session username
	sessionUsername, valErr := ValidateSessionUsername(c)
	if valErr != nil {
		return nil, valErr
	}

	// Validate payload (JSON body)
	if valErr := ValidatePayload(c, r); valErr != nil {
		return nil, valErr
	}

	// For activation, validate and set UserIP
	if valErr := ValidateUserIP(c.RealIP()); valErr != nil {
		return nil, valErr
	}
	r.UserIP = c.RealIP()

	// Get query parameters
	reqUser := c.QueryParam("authpf_username")

	// For activation, get and validate timeout
	if action == "activate" {
		reqTimeout := c.QueryParam("timeout")
		timeout, expiresAt, valErr := ValidateTimeout(reqTimeout)
		if valErr != nil {
			return nil, valErr
		}
		r.Timeout = timeout
		r.ExpiresAt = expiresAt
	}

	// Determine RBAC permission based on action
	rbacPermission := RBAC_ACTIVATE_OTHER_RULE
	if action == "deactivate" {
		rbacPermission = RBAC_DEACTIVATE_OTHER_RULE
	}

	// Validate and resolve target user
	targetUser, valErr := ResolveTargetUser(c, sessionUsername, reqUser, rbacPermission)
	if valErr != nil {
		return nil, valErr
	}
	r.Username = targetUser

	// Set UserID if available
	SetUserID(r)

	return r, nil
}

// ValidateAuthPFAnchor performs validations specific to the action (activate or deactivate)
// action should be either "activate" or "deactivate"
func ValidateAuthPFAnchor(r *AuthPFAnchor, action string) *ValidationError {
	// Determine session operation and permission based on action
	var sessionOp string
	var rbacPermission string

	if action == "activate" {
		sessionOp = SESSION_REGISTER
		rbacPermission = RBAC_ACTIVATE_OWN_RULE
	} else {
		sessionOp = SESSION_UNREGISTER
		rbacPermission = RBAC_DEACTIVATE_OWN_RULE
	}

	// Check permission
	if valErr := CheckPermission(r.Username, rbacPermission); valErr != nil {
		return valErr
	}

	// Check if session exists (or doesn't exist for deactivate)
	if valErr := CheckSessionExists(r.Username, logger, sessionOp); valErr != nil {
		return valErr
	}

	return nil
}

// SetUserID sets the UserID from config if available
func SetUserID(r *AuthPFAnchor) {
	if user, ok := config.Rbac.Users[r.Username]; ok && user.UserID > 0 {
		r.UserID = user.UserID
	}
}
