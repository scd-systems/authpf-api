package authpf

import (
	"fmt"
	"time"
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
	return fmt.Errorf("username not found in DB: %s", username)
}

// Clear DB
func (a *AnchorsDB) Flush() {
	*a = make(AnchorsDB)
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
		return &AuthPFAnchor{}, fmt.Errorf("missing or wrong parameter SetAnchor() func")
	}

	return &AuthPFAnchor{Username: username, Timeout: timeout, UserIP: userIp, UserID: userId, ExpiresAt: expireAt}, nil
}
