// Package authpf defines the public types used by the core and extensions.
// These types live outside internal/ so external extension modules can import them.
package authpf

import "time"

// AuthPFAnchor represents an anchor to store in anchorsDB.
type AuthPFAnchor struct {
	Username  string    `json:"username"`
	Timeout   string    `json:"timeout,omitempty"`
	UserIP    string    `json:"user_ip"`
	UserID    int       `json:"user_id"`
	ExpiresAt time.Time `json:"expire_at"`
}

// ReadOnlyAnchorsDB is the read-only interface exposed to extensions.
// Extensions can inspect anchors but cannot mutate the DB.
type ReadOnlyAnchorsDB interface {
	Get(username string) *AuthPFAnchor
	Len() int
	Range(fn func(*AuthPFAnchor) bool)
	IsActivated(username string) bool
	Snapshot() map[string]*AuthPFAnchor
}
