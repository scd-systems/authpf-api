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
type AnchorsDB struct {
	mu   sync.Mutex
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

	a.data[r.Username] = r
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
	a.mu.Lock()
	defer a.mu.Unlock()

	return a.data[username] != nil
}

// Get returns the anchor for the given username, or nil if not found.
func (a *AnchorsDB) Get(username string) *authpf.AuthPFAnchor {
	a.mu.Lock()
	defer a.mu.Unlock()

	return a.data[username]
}

func (a *AnchorsDB) GetAll() map[string]*AuthPFAnchor {
	a.mu.Lock()
	defer a.mu.Unlock()

	result := make(map[string]*AuthPFAnchor, len(a.data))
	for key, anchor := range a.data {
		result[key] = anchor
	}
	return result
}

// Len returns the number of active anchors.
func (a *AnchorsDB) Len() int {
	a.mu.Lock()
	defer a.mu.Unlock()

	return len(a.data)
}

// Range iterates over all active anchors.
func (a *AnchorsDB) Range(fn func(*authpf.AuthPFAnchor) bool) {
	a.mu.Lock()
	defer a.mu.Unlock()

	for _, v := range a.data {
		if !fn(v) {
			break
		}
	}
}

// Snapshot returns a copy of the anchors map.
func (a *AnchorsDB) Snapshot() map[string]*authpf.AuthPFAnchor {
	a.mu.Lock()
	defer a.mu.Unlock()

	result := make(map[string]*authpf.AuthPFAnchor, len(a.data))
	for k, v := range a.data {
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
