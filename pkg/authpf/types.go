// Package authpf defines the public types used by the core and extensions.
// These types live outside internal/ so external extension modules can import them.
package authpf

import "time"

// UserIPUnknown marks an anchor adopted by the startup import: pf's anchor list
// (-sA) does not expose the -D user_ip macro that loaded the anchor, so the API
// does not know the address of an adopted anchor.
const UserIPUnknown = "unknown"

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
