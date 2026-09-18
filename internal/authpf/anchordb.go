package authpf

import (
	"fmt"
	"time"

	"github.com/scd-systems/authpf-api/pkg/authpf"
)

// Re-export public types so existing internal imports continue to work.
type AuthPFAnchor = authpf.AuthPFAnchor
type ReadOnlyAnchorsDB = authpf.ReadOnlyAnchorsDB

// Map of AuthPFAnchors
type AnchorsDB map[string]*authpf.AuthPFAnchor

func New() *AnchorsDB {
	anchorsDB := make(AnchorsDB)
	return &anchorsDB
}

func (a *AnchorsDB) Add(r *authpf.AuthPFAnchor) {
	(*a)[r.Username] = r
}

func (a *AnchorsDB) Remove(username string) error {
	if (*a)[username] == nil {
		return fmt.Errorf("username not found in DB: %s", username)
	}
	delete(*a, username)
	return nil
}

// Clear DB
func (a *AnchorsDB) Flush() {
	*a = make(AnchorsDB)
}

func (a *AnchorsDB) IsActivated(username string) bool {
	return (*a)[username] != nil
}

// Get returns the anchor for the given username, or nil if not found.
func (a *AnchorsDB) Get(username string) *authpf.AuthPFAnchor {
	return (*a)[username]
}

// Len returns the number of active anchors.
func (a *AnchorsDB) Len() int {
	return len(*a)
}

// Range iterates over all active anchors.
func (a *AnchorsDB) Range(fn func(*authpf.AuthPFAnchor) bool) {
	for _, v := range *a {
		if !fn(v) {
			break
		}
	}
}

// Snapshot returns a copy of the anchors map.
func (a *AnchorsDB) Snapshot() map[string]*authpf.AuthPFAnchor {
	result := make(AnchorsDB, len(*a))
	for k, v := range *a {
		result[k] = v
	}
	return result
}

func SetAnchor(username string, timeout string, userIp string, userId int, expireAt time.Time) (*authpf.AuthPFAnchor, error) {
	if len(username) < 1 || len(timeout) < 1 || len(userIp) < 1 || userId < 0 || userId > 65535 {
		return &authpf.AuthPFAnchor{}, fmt.Errorf("missing or wrong parameter SetAnchor() func")
	}
	return &authpf.AuthPFAnchor{Username: username, Timeout: timeout, UserIP: userIp, UserID: userId, ExpiresAt: expireAt}, nil
}
