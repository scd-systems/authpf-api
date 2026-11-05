package authpf

import (
	"fmt"
	"sync"
	"time"

	"github.com/scd-systems/authpf-api/pkg/authpf"
)

// Re-export public types so existing internal imports continue to work.
type AuthPFAnchor = authpf.AuthPFAnchor
type ReadOnlyAnchorsDB = authpf.ReadOnlyAnchorsDB

// AnchorsDB is an object with AuthPFAnchors keyed by username.
// Its methods protect map access by mutex and return copies of stored anchors.
type AnchorsDB struct {
	mu   sync.RWMutex
	data map[string]*authpf.AuthPFAnchor
}

func New() *AnchorsDB {
	return &AnchorsDB{
		data: make(map[string]*authpf.AuthPFAnchor),
	}
}

func (a *AnchorsDB) Add(r *authpf.AuthPFAnchor) {
	a.mu.Lock()
	defer a.mu.Unlock()

	copy := *r
	a.data[copy.Username] = &copy
}

func (a *AnchorsDB) Remove(username string) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.data[username] == nil {
		return fmt.Errorf("username not found in DB: %s", username)
	}
	delete(a.data, username)
	return nil
}

// Clear DB
func (a *AnchorsDB) Flush() {
	a.mu.Lock()
	defer a.mu.Unlock()

	clear(a.data)
}

func (a *AnchorsDB) IsActivated(username string) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()

	return a.data[username] != nil
}

// Get returns the anchor for the given username, or nil if not found.
func (a *AnchorsDB) Get(username string) *authpf.AuthPFAnchor {
	a.mu.RLock()
	defer a.mu.RUnlock()

	return cloneAnchor(a.data[username])
}

func (a *AnchorsDB) GetAll() map[string]*AuthPFAnchor {
	a.mu.RLock()
	defer a.mu.RUnlock()

	result := make(map[string]*AuthPFAnchor, len(a.data))
	for key, anchor := range a.data {
		result[key] = cloneAnchor(anchor)
	}
	return result
}

// Len returns the number of active anchors.
func (a *AnchorsDB) Len() int {
	a.mu.RLock()
	defer a.mu.RUnlock()

	return len(a.data)
}

// Range iterates over all active anchors.
func (a *AnchorsDB) Range(fn func(*authpf.AuthPFAnchor) bool) {
	for _, v := range a.GetAll() {
		if !fn(v) {
			break
		}
	}
}

// Snapshot returns a copy of the anchors map.
func (a *AnchorsDB) Snapshot() map[string]*authpf.AuthPFAnchor {
	return a.GetAll()
}

func SetAnchor(username string, timeout string, userIp string, userId int, expireAt time.Time) (*authpf.AuthPFAnchor, error) {
	if len(username) < 1 || len(timeout) < 1 || len(userIp) < 1 || userId < 0 || userId > 65535 {
		return &authpf.AuthPFAnchor{}, fmt.Errorf("missing or wrong parameter SetAnchor() func")
	}
	return &authpf.AuthPFAnchor{Username: username, Timeout: timeout, UserIP: userIp, UserID: userId, ExpiresAt: expireAt}, nil
}

func cloneAnchor(anchor *authpf.AuthPFAnchor) *authpf.AuthPFAnchor {
	if anchor == nil {
		return nil
	}

	copy := *anchor
	return &copy
}
