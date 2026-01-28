package main

import (
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/rs/zerolog"
)

// ValidationError represents a validation error with HTTP status and message
type ValidationError struct {
	StatusCode int
	Message    string
	Details    string
}

// Error implements the error interface for ValidationError
func (ve *ValidationError) Error() string {
	if ve.Details != "" {
		return fmt.Sprintf("%s: %s", ve.Message, ve.Details)
	}
	return ve.Message
}

// ValidateSessionUsername extracts and validates the username from JWT token in Echo context
// Returns the username if valid, or a ValidationError if validation fails
func ValidateSessionUsername(c echo.Context) (string, *ValidationError) {
	username, ok := c.Get("username").(string)
	if !ok || username == "" {
		return "", &ValidationError{
			StatusCode: http.StatusUnauthorized,
			Message:    "invalid username in token",
			Details:    "username not found or empty in JWT claims",
		}
	}
	return username, nil
}

// ValidatePayload validates the JSON payload from the request and binds it to the AuthPFAnchor
func ValidatePayload(c echo.Context, r *AuthPFAnchor) *ValidationError {
	if err := c.Bind(r); err != nil {
		return &ValidationError{
			StatusCode: http.StatusBadRequest,
			Message:    "invalid JSON payload",
			Details:    err.Error(),
		}
	}
	return nil
}

// ValidateTimeout validates the timeout parameter and returns the parsed duration and expiration time
// If timeout is empty, uses the default from config
func ValidateTimeout(timeoutStr string) (string, time.Time, *ValidationError) {
	if timeoutStr == "" {
		timeoutStr = config.AuthPF.Timeout
	}

	if timeoutStr == "" {
		// No timeout specified and no default configured
		return "", time.Time{}, nil
	}

	d, err := time.ParseDuration(timeoutStr)
	if err != nil {
		return "", time.Time{}, &ValidationError{
			StatusCode: http.StatusBadRequest,
			Message:    "invalid timeout format",
			Details:    fmt.Sprintf("timeout must be a valid duration (e.g., '1h', '30m'), got: %s", timeoutStr),
		}
	}

	if d < time.Minute {
		return "", time.Time{}, &ValidationError{
			StatusCode: http.StatusBadRequest,
			Message:    "timeout must be at least 1 minute",
			Details:    fmt.Sprintf("provided timeout: %v", d),
		}
	}

	if d > 24*time.Hour {
		return "", time.Time{}, &ValidationError{
			StatusCode: http.StatusBadRequest,
			Message:    "timeout cannot exceed 24 hours",
			Details:    fmt.Sprintf("provided timeout: %v", d),
		}
	}

	expiresAt := time.Now().Add(d)
	return timeoutStr, expiresAt, nil
}

// ValidateUsername validates the username format and existence in config
func ValidateUsername(username string) *ValidationError {
	if err := config.validateUsername(username); err != nil {
		return &ValidationError{
			StatusCode: http.StatusBadRequest,
			Message:    "invalid username",
			Details:    err.Error(),
		}
	}
	return nil
}

// CheckPermission checks if a user has a specific permission
// Returns a ValidationError if the user doesn't have the permission
func CheckPermission(username string, permission string) *ValidationError {
	if err := config.validateUserPermissions(username, permission); err != nil {
		return &ValidationError{
			StatusCode: http.StatusForbidden,
			Message:    "permission denied",
			Details:    err.Error(),
		}
	}
	return nil
}

// ResolveTargetUser resolves the target user for an operation
// If requestedUser is empty or equals the session user, returns the session user
// If requestedUser differs from session user, checks if the session user has permission to operate on other users
// Returns the resolved username or a ValidationError
func ResolveTargetUser(c echo.Context, sessionUser, requestedUser string, requiredPermission string) (string, *ValidationError) {
	// If no specific user requested, use session user
	if requestedUser == "" || requestedUser == sessionUser {
		return sessionUser, nil
	}

	// Check if session user has permission to operate on other users
	if permErr := CheckPermission(sessionUser, requiredPermission); permErr != nil {
		return "", permErr
	}

	// Validate the requested username exists
	if valErr := ValidateUsername(requestedUser); valErr != nil {
		logger.Info().Str("status", "rejected").Str("user", sessionUser).Str("requested_user", requestedUser).Msg("invalid requested username")
		return "", valErr
	}

	return requestedUser, nil
}

// CheckSessionExists checks if an active session already exists for the user
// Returns a ValidationError if a session already exists
func CheckSessionExists(username string, logger zerolog.Logger, mode string) *ValidationError {
	_, exists := anchorsDB[username]

	// Check if the current state matches the expected state for the mode
	isError := (mode == "activate" && exists) || (mode == "deactivate" && !exists) || (mode != "activate" && mode != "deactivate")

	if !isError {
		return nil
	}

	// Determine error message based on mode
	var msg, detail string
	statusCode := http.StatusMethodNotAllowed

	switch mode {
	case "activate":
		msg = "authpf rule for user already activated"
		detail = fmt.Sprintf("user %q already has an active authpf rule", username)
	case "deactivate":
		msg = "authpf rule for user not activated"
		detail = fmt.Sprintf("user %q does not have an active authpf rule", username)
	default:
		msg = "internal server error"
		detail = fmt.Sprintf("invalid CheckSessionExists mode: %s", mode)
		statusCode = http.StatusInternalServerError
	}

	return &ValidationError{
		StatusCode: statusCode,
		Message:    msg,
		Details:    detail,
	}
}

// RespondWithValidationError sends a JSON error response based on ValidationError
func RespondWithValidationError(c echo.Context, valErr *ValidationError) error {
	if valErr == nil {
		return nil
	}
	c.Set("auth", valErr.Details)

	return c.JSON(valErr.StatusCode, echo.Map{
		"error":   valErr.Message,
		"details": valErr.Details,
	})
}

// RespondWithValidationErrorStatus sends a JSON error response with status field
func RespondWithValidationErrorStatus(c echo.Context, valErr *ValidationError) error {
	if valErr == nil {
		return nil
	}
	c.Set("auth", valErr.Details)

	return c.JSON(valErr.StatusCode, echo.Map{
		"status":  "rejected",
		"message": valErr.Message,
		"details": valErr.Details,
	})
}

// ValidateUserIP validates that the provided IP address is a valid IPv4 or IPv6 address
// Returns a ValidationError if the IP is invalid or empty
func ValidateUserIP(ip string) *ValidationError {
	if ip == "" {
		return &ValidationError{
			StatusCode: http.StatusBadRequest,
			Message:    "invalid IP address",
			Details:    "IP address cannot be empty",
		}
	}

	// Parse the IP address - net.ParseIP returns nil if the IP is invalid
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return &ValidationError{
			StatusCode: http.StatusBadRequest,
			Message:    "invalid IP address",
			Details:    fmt.Sprintf("'%s' is not a valid IPv4 or IPv6 address", ip),
		}
	}

	return nil
}
