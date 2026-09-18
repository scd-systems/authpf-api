package authpf_test

import (
	"testing"
	"time"

	"github.com/scd-systems/authpf-api/internal/authpf"
)

// Compile-time assertion: *AnchorsDB implements ReadOnlyAnchorsDB.
var _ authpf.ReadOnlyAnchorsDB = (*authpf.AnchorsDB)(nil)

// TestReadOnlyAnchorsDB_Interface verifies the interface is satisfied
// and that the read methods work correctly.
func TestReadOnlyAnchorsDB_Interface(t *testing.T) {
	db := authpf.New()
	var ro authpf.ReadOnlyAnchorsDB = db

	// Empty DB
	if ro.Len() != 0 {
		t.Errorf("expected Len()=0, got %d", ro.Len())
	}
	if ro.Get("nobody") != nil {
		t.Error("expected Get()=nil for missing user")
	}
	if ro.IsActivated("nobody") {
		t.Error("expected IsActivated()=false for missing user")
	}

	// Add via concrete type, read via interface
	anchor, _ := authpf.SetAnchor("alice", "1h", "10.0.0.1", 1000, time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC))
	db.Add(anchor)

	if ro.Len() != 1 {
		t.Errorf("expected Len()=1, got %d", ro.Len())
	}
	if got := ro.Get("alice"); got == nil || got.Username != "alice" {
		t.Errorf("expected Get('alice') to return anchor, got %v", got)
	}
	if !ro.IsActivated("alice") {
		t.Error("expected IsActivated('alice')=true")
	}

	// Range
	var seen []string
	ro.Range(func(a *authpf.AuthPFAnchor) bool {
		seen = append(seen, a.Username)
		return true
	})
	if len(seen) != 1 || seen[0] != "alice" {
		t.Errorf("expected Range to yield ['alice'], got %v", seen)
	}
}

// TestReadOnlyAnchorsDB_NoMutation verifies that mutation methods
// are NOT available on the interface. This test exists as documentation;
// the enforcement is compile-time (the methods simply don't exist on the interface).
func TestReadOnlyAnchorsDB_NoMutation(t *testing.T) {
	db := authpf.New()
	var ro authpf.ReadOnlyAnchorsDB = db

	// The following would not compile (commented to prove the point):
	// ro.Add(...)       // compile error: Add not in interface
	// ro.Remove(...)     // compile error: Remove not in interface
	// ro.Flush()         // compile error: Flush not in interface

	// Read-only operations work:
	_ = ro.Len()
	_ = ro.Get("nobody")
	_ = ro.IsActivated("nobody")
	ro.Range(func(a *authpf.AuthPFAnchor) bool { return true })
}
