package api

import (
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strings"

	"github.com/labstack/echo/v4"
	"github.com/scd-systems/authpf-api/internal/authpf"
	"github.com/scd-systems/authpf-api/internal/errors"
	"github.com/scd-systems/authpf-api/internal/exec"
	"github.com/scd-systems/authpf-api/pkg/config"
)

func (h *Handler) CheckAnchorIsActivated(c echo.Context) (bool, *errors.APIError) {
	sessionUsername, err := h.resolveAnchorUsername(c)
	if err != nil {
		return false, &errors.APIError{
			HttpStatusCode: http.StatusInternalServerError,
			StatusCode:     -1,
			Message:        "unable to lookup username",
			Details:        "No username in context found",
		}
	}
	if h.db.IsActivated(sessionUsername) {
		return true, &errors.APIError{
			HttpStatusCode: http.StatusAlreadyReported,
			StatusCode:     -1,
			Message:        "Anchor already activated",
			Details:        "Anchor from user already in AnchorDB",
		}
	}
	return false, nil
}

// Check Username and JSON Payload
func (h *Handler) CheckSessionUsername(c echo.Context) *errors.APIError {
	if _, err := h.sessionUsername(c); err != nil {
		return err
	}
	return nil
}

// Get Username from request
func (h *Handler) sessionUsername(c echo.Context) (string, *errors.APIError) {
	username, ok := c.Get("username").(string)
	if !ok || username == "" {
		return "", &errors.APIError{
			HttpStatusCode: http.StatusUnauthorized,
			StatusCode:     -1,
			Message:        "invalid username in token",
			Details:        "username not found or empty in JWT claims",
		}
	}
	return username, nil
}

// Check if AuthPFAnchor can be bind to payload
func (h *Handler) CheckJSONPayload(c echo.Context, r *authpf.AuthPFAnchor) *errors.APIError {
	if err := c.Bind(r); err != nil {
		return &errors.APIError{
			HttpStatusCode: http.StatusBadRequest,
			StatusCode:     -1,
			Message:        "invalid JSON payload",
			Details:        err.Error(),
		}
	}
	return nil
}

// Call Exec activate anchor
func (h *Handler) CallExecActivateAnchor(c echo.Context, r *authpf.AuthPFAnchor) *errors.APIError {
	e := exec.New(h.logger, h.config, h.db)

	result := e.LoadAuthPFAnchor(r)
	msg := fmt.Sprintf("Exec: '%s %s', ExitCode: %d, Stdout: %s, StdErr: %s", result.Command, strings.Join(result.Args, " "), result.ExitCode, result.Stdout, result.Stderr)
	h.logger.Trace().Str("user", c.Get("username").(string)).Msg(msg)

	if result.ExitCode != 0 {
		return &errors.APIError{
			HttpStatusCode: http.StatusInternalServerError,
			StatusCode:     result.ExitCode,
			Message:        "failed to load anchor rules",
			Details:        result.Stderr,
		}
	}
	return nil
}

func (h *Handler) CallExecDeactivateAnchor(r *authpf.AuthPFAnchor) *errors.APIError {
	e := exec.New(h.logger, h.config, h.db)

	multiResult := e.UnloadAuthPFAnchor(r)

	// Log all commands
	for i, result := range multiResult.Results {
		msg := fmt.Sprintf("Exec [%d/%d]: '%s %s', ExitCode: %d, Stdout: %s, StdErr: %s",
			i+1, len(multiResult.Results), result.Command, strings.Join(result.Args, " "),
			result.ExitCode, result.Stdout, result.Stderr)
		h.logger.Debug().Str("user", r.Username).Msg(msg)
	}
	if multiResult.Error != nil {
		return &errors.APIError{
			HttpStatusCode: http.StatusInternalServerError,
			StatusCode:     -1,
			Message:        "failed to unload anchor rules",
			Details:        "check server logs",
		}
	}
	return nil
}

func (h *Handler) CallExecDeactivateAllAnchors(r *authpf.AuthPFAnchor) *errors.APIError {
	e := exec.New(h.logger, h.config, h.db)

	multiResult := e.UnloadAllAuthPFAnchors()

	// Log all commands
	for i, result := range multiResult.Results {
		msg := fmt.Sprintf("Exec [%d/%d]: '%s %s', ExitCode: %d, Stdout: %s, StdErr: %s",
			i+1, len(multiResult.Results), result.Command, strings.Join(result.Args, " "),
			result.ExitCode, result.Stdout, result.Stderr)
		h.logger.Debug().Str("user", r.Username).Msg(msg)
	}
	if multiResult.Error != nil {
		return &errors.APIError{
			HttpStatusCode: http.StatusInternalServerError,
			StatusCode:     -1,
			Message:        "failed to unload anchor rules",
			Details:        "check server logs",
		}
	}
	return nil
}

// Validate User role permissions
func (h *Handler) CheckSessionUserPermission(c echo.Context, action string) *errors.APIError {
	var permission string
	sessionUsername, err := h.sessionUsername(c)
	if err != nil {
		return &errors.APIError{
			HttpStatusCode: http.StatusForbidden,
			StatusCode:     -1,
			Message:        "permission denied",
			Details:        err.Error(),
		}
	}

	authpfUsername, err := h.resolveAnchorUsername(c)
	if err != nil {
		return &errors.APIError{
			HttpStatusCode: http.StatusForbidden,
			StatusCode:     -1,
			Message:        "permission denied",
			Details:        err.Error(),
		}
	}

	flag := c.Get("Flag")
	switch flag {
	case "view-all": // Case for view all anchors
		permission = config.RBAC_GET_STATUS_OTHER_RULE
	case "delete-all": // Case for delete all anchors
		permission = config.RBAC_DEACTIVATE_OTHER_RULE
	default:
		result, err := resolvePermission(sessionUsername, authpfUsername, action)
		if err != nil {
			return &errors.APIError{
				HttpStatusCode: http.StatusForbidden,
				StatusCode:     -1,
				Message:        "permission denied",
				Details:        err.Error(),
			}
		}
		permission = result
	}

	if err := h.validateUserPermissions(sessionUsername, permission); err != nil {
		return &errors.APIError{
			HttpStatusCode: http.StatusForbidden,
			StatusCode:     -1,
			Message:        "permission denied",
			Details:        err.Error(),
		}
	}

	return nil
}

// Check session User, Anchor User and Action to resolve correct RBAC permission
func resolvePermission(sessionUsername, authpfUsername, action string) (string, error) {
	var permission string
	switch action {
	case config.SESSION_REGISTER:
		if authpfUsername != sessionUsername {
			permission = config.RBAC_ACTIVATE_OTHER_RULE
		} else {
			permission = config.RBAC_ACTIVATE_OWN_RULE
		}
	case config.SESSION_UNREGISTER:
		if authpfUsername != sessionUsername {
			permission = config.RBAC_DEACTIVATE_OTHER_RULE
		} else {
			permission = config.RBAC_DEACTIVATE_OWN_RULE
		}
	case config.SESSION_VIEW:
		if authpfUsername != sessionUsername {
			permission = config.RBAC_GET_STATUS_OTHER_RULE
		} else {
			permission = config.RBAC_GET_STATUS_OWN_RULE
		}
	default:
		return permission, fmt.Errorf("session action: %s cannot be used", action)
	}
	return permission, nil
}

func (h *Handler) validateUserPermissions(username string, permission string) error {

	user, ok := h.config.Rbac.Users[username]
	if !ok {
		return fmt.Errorf("user %q not found", username)
	}

	role, ok := h.config.Rbac.Roles[user.Role]
	if !ok {
		return fmt.Errorf("role %q for user %q does not exists", user.Role, username)
	}

	for _, p := range role.Permissions {
		if p == permission {
			return nil
		}
	}

	return fmt.Errorf("user %q does not have the permission [%q] (Role: %s)", username, permission, user.Role)
}

func (h *Handler) CheckSessionUserIP(c echo.Context) *errors.APIError {
	if err := checkUserIP(c.RealIP()); err != nil {
		return err
	}
	return nil
}

func checkUserIP(ip string) *errors.APIError {
	if ip == "" {
		return &errors.APIError{
			HttpStatusCode: http.StatusBadRequest,
			StatusCode:     -1,
			Message:        "invalid IP address",
			Details:        "IP address cannot be empty",
		}
	}

	// Parse the IP address - net.ParseIP returns nil if the IP is invalid
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return &errors.APIError{
			HttpStatusCode: http.StatusBadRequest,
			StatusCode:     -1,
			Message:        "invalid IP address",
			Details:        fmt.Sprintf("'%s' is not a valid IPv4 or IPv6 address", ip),
		}
	}
	return nil
}

func (h *Handler) GetAnchorFromContext(c echo.Context) (*authpf.AuthPFAnchor, *errors.APIError) {
	anchor := &authpf.AuthPFAnchor{}

	authpf_username, err := h.resolveAnchorUsername(c)
	if err != nil {
		return anchor, err
	}

	timeout, err := h.resolveAnchorTimeout(c)
	if err != nil {
		return anchor, err
	}
	userIp := c.RealIP()
	userId := h.getUserID(authpf_username)

	expireAt, err1 := exec.CalculateAnchorExpire(timeout)
	if err1 != nil {
		return nil, &errors.APIError{
			HttpStatusCode: http.StatusInternalServerError,
			StatusCode:     -1,
			Message:        "Unable to set Anchor for user",
			Details:        err1.Error(),
		}
	}

	anchor = &authpf.AuthPFAnchor{
		Username:  authpf_username,
		Timeout:   timeout,
		UserIP:    userIp,
		UserID:    userId,
		ExpiresAt: expireAt,
	}
	return anchor, nil
}

// Extract the Anchor Username from Request (query)
func (h *Handler) resolveAnchorUsername(c echo.Context) (string, *errors.APIError) {
	reqUser, err := h.sessionUsername(c)
	if err != nil {
		return "", err
	}
	queryUser := c.QueryParam("authpf_username")
	if queryUser != "" {
		if err = h.validateUsername(queryUser); err != nil {
			return "", err
		}
		return queryUser, nil
	}
	return reqUser, nil
}

// Resolve the Timeout from request if available, use default instead
func (h *Handler) resolveAnchorTimeout(c echo.Context) (string, *errors.APIError) {
	reqTimeout := c.QueryParam("timeout")
	if reqTimeout != "" {
		if len(reqTimeout) > 10 {
			return "", &errors.APIError{
				HttpStatusCode: http.StatusBadRequest,
				StatusCode:     -1,
				Message:        "timeout parameter too long",
				Details:        "maximum 10 characters allowed",
			}
		}
		if err := exec.ValidateTimeout(reqTimeout); err != nil {
			return "", err
		}
		return reqTimeout, nil
	}
	return h.config.AuthPF.Timeout, nil
}

func (h *Handler) getUserID(username string) int {
	if user, ok := h.config.Rbac.Users[username]; ok && user.UserID > 0 {
		return user.UserID
	}
	return 0
}

// Validate the username string and if exist
func (h *Handler) validateUsername(username string) *errors.APIError {
	if len(username) > 255 {
		return &errors.APIError{
			HttpStatusCode: http.StatusBadRequest,
			StatusCode:     -1,
			Message:        "invalid username",
			Details:        "username too long",
		}
	}
	if !regexp.MustCompile(`^[a-zA-Z0-9_-]+$`).MatchString(username) {
		return &errors.APIError{
			HttpStatusCode: http.StatusBadRequest,
			StatusCode:     -1,
			Message:        "invalid username format",
			Details:        "username contains invalid characters",
		}
	}

	if _, ok := h.config.Rbac.Users[username]; !ok {
		return &errors.APIError{
			HttpStatusCode: http.StatusBadRequest,
			StatusCode:     -1,
			Message:        "user not found",
			Details:        "requested user does not exist",
		}
	}
	return nil
}
