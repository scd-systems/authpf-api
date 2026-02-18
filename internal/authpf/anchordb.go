package authpf

import (
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/scd-systems/authpf-api/internal/validation"
	"github.com/scd-systems/authpf-api/pkg/config"
)

// AuthPFAnchor represents an anchor to store in anchorsDB
type AuthPFAnchor struct {
	Username  string    `json:"username"`
	Timeout   string    `json:"timeout,omitempty"`
	UserIP    string    `json:"user_ip"`
	UserID    int       `json:"user_id"`
	ExpiresAt time.Time `json:"expire_at"`
}

// Map of AuthPFAnchors
type AnchorsDB map[string]*AuthPFAnchor

func New() *AnchorsDB {
	anchorsDB := make(AnchorsDB)
	return &anchorsDB
}

func (a *AnchorsDB) Add(r *AuthPFAnchor) {
	(*a)[r.Username] = r
}

func (a *AnchorsDB) Remove(username string) error {
	for idx, v := range *a {
		if v.Username == username {
			delete(*a, idx)
			return nil
		}
	}
	return fmt.Errorf("Not found username in DB: %s", username)
}

func (a *AnchorsDB) IsActivated(username string) bool {
	for _, v := range *a {
		if v.Username == username {
			return true
		}
	}
	return false
}

func SetAnchor(username string, timeout string, userIp string, userId int, expireAt time.Time) (*AuthPFAnchor, error) {
	if len(username) < 1 || len(timeout) < 1 || len(userIp) < 1 || userId < 0 || userId > 65535 {
		return &AuthPFAnchor{}, fmt.Errorf("Missing or wrong parameter SetAnchor() func")
	}

	return &AuthPFAnchor{Username: username, Timeout: timeout, UserIP: userIp, UserID: userId, ExpiresAt: expireAt}, nil
}

// Add timeout to current time from server as Expire Date
func CalculateAnchorExpire(timeoutStr string) (time.Time, error) {
	d, err := time.ParseDuration(timeoutStr)
	if err != nil {
		return time.Time{}, err
	}
	return time.Now().Add(d), nil
}

// SetUserID sets the UserID from config if available
func SetUserID(r *AuthPFAnchor, cfg *config.ConfigFile) {
	if user, ok := cfg.Rbac.Users[r.Username]; ok && user.UserID > 0 {
		r.UserID = user.UserID
	}
}

func ValidateJsonRequestPayload(c echo.Context, r *AuthPFAnchor) *validation.ValidationError {
	if err := c.Bind(r); err != nil {
		return &validation.ValidationError{
			StatusCode: http.StatusBadRequest,
			Message:    "invalid JSON payload",
			Details:    err.Error(),
		}
	}
	return nil
}

func ValidateRequestUsername(c echo.Context) (string, *validation.ValidationError) {
	username, ok := c.Get("username").(string)
	if !ok || username == "" {
		return "", &validation.ValidationError{
			StatusCode: http.StatusUnauthorized,
			Message:    "invalid username in token",
			Details:    "username not found or empty in JWT claims",
		}
	}
	return username, nil
}

func ValidateUserIP(ip string) *validation.ValidationError {
	if ip == "" {
		return &validation.ValidationError{
			StatusCode: http.StatusBadRequest,
			Message:    "invalid IP address",
			Details:    "IP address cannot be empty",
		}
	}

	// Parse the IP address - net.ParseIP returns nil if the IP is invalid
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return &validation.ValidationError{
			StatusCode: http.StatusBadRequest,
			Message:    "invalid IP address",
			Details:    fmt.Sprintf("'%s' is not a valid IPv4 or IPv6 address", ip),
		}
	}

	return nil
}
