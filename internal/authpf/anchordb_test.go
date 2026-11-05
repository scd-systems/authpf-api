package authpf

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// TestSetAnchor_Success tests successful anchor creation
func TestSetAnchor_Success(t *testing.T) {
	expiresAt := time.Now().Add(1 * time.Hour)

	anchor, err := SetAnchor("testuser", "1h", "192.168.1.1", 1000, expiresAt)

	assert.NoError(t, err)
	assert.NotNil(t, anchor)
	assert.Equal(t, "testuser", anchor.Username)
	assert.Equal(t, "1h", anchor.Timeout)
	assert.Equal(t, "192.168.1.1", anchor.UserIP)
	assert.Equal(t, 1000, anchor.UserID)
	assert.Equal(t, expiresAt, anchor.ExpiresAt)
}

// TestSetAnchor_InvalidUsername tests with empty username
func TestSetAnchor_InvalidUsername(t *testing.T) {
	expiresAt := time.Now().Add(1 * time.Hour)

	anchor, err := SetAnchor("", "1h", "192.168.1.1", 1000, expiresAt)

	assert.Error(t, err)
	assert.NotNil(t, anchor) // Returns empty anchor on error
}

// TestSetAnchor_InvalidTimeout tests with empty timeout
func TestSetAnchor_InvalidTimeout(t *testing.T) {
	expiresAt := time.Now().Add(1 * time.Hour)

	anchor, err := SetAnchor("testuser", "", "192.168.1.1", 1000, expiresAt)

	assert.Error(t, err)
	assert.NotNil(t, anchor)
}

// TestSetAnchor_InvalidIP tests with empty IP
func TestSetAnchor_InvalidIP(t *testing.T) {
	expiresAt := time.Now().Add(1 * time.Hour)

	anchor, err := SetAnchor("testuser", "1h", "", 1000, expiresAt)

	assert.Error(t, err)
	assert.NotNil(t, anchor)
}

// TestSetAnchor_InvalidUserID tests with invalid user ID
func TestSetAnchor_InvalidUserID(t *testing.T) {
	expiresAt := time.Now().Add(1 * time.Hour)

	tests := []struct {
		name   string
		userID int
		valid  bool
	}{
		{"negative ID", -1, false},
		{"zero ID", 0, true},
		{"valid ID", 1000, true},
		{"max valid ID", 65535, true},
		{"ID too large", 65536, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			anchor, err := SetAnchor("testuser", "1h", "192.168.1.1", tt.userID, expiresAt)

			if tt.valid {
				assert.NoError(t, err)
				assert.Equal(t, tt.userID, anchor.UserID)
			} else {
				assert.Error(t, err)
			}
		})
	}
}

// TestAnchorsDB_Add tests adding anchors to the database
func TestAnchorsDB_Add(t *testing.T) {
	db := New()

	anchor := &AuthPFAnchor{
		Username: "testuser",
		UserID:   1000,
		UserIP:   "192.168.1.1",
	}

	db.Add(anchor)

	assert.Equal(t, 1, len(db.data))
	assert.Equal(t, anchor, db.data["testuser"])
}

// TestAnchorsDB_Remove_Success tests removing an existing anchor
func TestAnchorsDB_Remove_Success(t *testing.T) {
	db := New()

	anchor := &AuthPFAnchor{
		Username: "testuser",
		UserID:   1000,
	}

	db.Add(anchor)
	assert.Equal(t, 1, len(db.data))

	err := db.Remove("testuser")

	assert.NoError(t, err)
	assert.Equal(t, 0, len(db.data))
}

// TestAnchorsDB_Remove_NotFound tests removing a non-existent anchor
func TestAnchorsDB_Remove_NotFound(t *testing.T) {
	db := New()

	err := db.Remove("nonexistent")

	assert.Error(t, err)
}

// TestAnchorsDB_IsActivated_True tests checking if an activated user exists
func TestAnchorsDB_IsActivated_True(t *testing.T) {
	db := New()

	anchor := &AuthPFAnchor{
		Username: "testuser",
		UserID:   1000,
	}

	db.Add(anchor)

	isActivated := db.IsActivated("testuser")

	assert.True(t, isActivated)
}

// TestAnchorsDB_IsActivated_False tests checking if a non-activated user exists
func TestAnchorsDB_IsActivated_False(t *testing.T) {
	db := New()

	isActivated := db.IsActivated("nonexistent")

	assert.False(t, isActivated)
}

// TestAnchorsDB_MultipleAnchors tests managing multiple anchors
func TestAnchorsDB_MultipleAnchors(t *testing.T) {
	db := New()

	anchors := []*AuthPFAnchor{
		{Username: "user1", UserID: 1000},
		{Username: "user2", UserID: 2000},
		{Username: "user3", UserID: 3000},
	}

	for _, anchor := range anchors {
		db.Add(anchor)
	}

	assert.Equal(t, 3, len(db.data))

	for _, anchor := range anchors {
		assert.True(t, db.IsActivated(anchor.Username))
	}

	err := db.Remove("user2")
	assert.NoError(t, err)
	assert.Equal(t, 2, len(db.data))
	assert.False(t, db.IsActivated("user2"))
	assert.True(t, db.IsActivated("user1"))
	assert.True(t, db.IsActivated("user3"))
}

// TestAnchorsDB_New tests creating a new empty database
func TestAnchorsDB_New(t *testing.T) {
	db := New()

	assert.NotNil(t, db.data)
	assert.Equal(t, 0, len(db.data))
}

// TestAuthPFAnchor_Structure tests the AuthPFAnchor struct fields
func TestAuthPFAnchor_Structure(t *testing.T) {
	expiresAt := time.Now().Add(1 * time.Hour)

	anchor := &AuthPFAnchor{
		Username:  "testuser",
		Timeout:   "1h",
		UserIP:    "192.168.1.1",
		UserID:    1000,
		ExpiresAt: expiresAt,
	}

	assert.Equal(t, "testuser", anchor.Username)
	assert.Equal(t, "1h", anchor.Timeout)
	assert.Equal(t, "192.168.1.1", anchor.UserIP)
	assert.Equal(t, 1000, anchor.UserID)
	assert.Equal(t, expiresAt, anchor.ExpiresAt)
}

func TestAnchorsDBGetAll(t *testing.T) {
	first := &AuthPFAnchor{Username: "first"}
	second := &AuthPFAnchor{Username: "second"}

	db := &AnchorsDB{
		data: map[string]*AuthPFAnchor{
			"first":  first,
			"second": second,
		},
	}

	got := db.GetAll()

	if len(got) != 2 {
		t.Fatalf("GetAll() returned %d entries, want 2", len(got))
	}
	if got["first"] == first || *got["first"] != *first {
		t.Errorf(`GetAll()["first"] = %v, want an equal but independent copy of %v`, got["first"], first)
	}
	if got["second"] == second || *got["second"] != *second {
		t.Errorf(`GetAll()["second"] = %v, want an equal but independent copy of %v`, got["second"], second)
	}

	// Mutating either returned layer must not affect the database.
	delete(got, "first")
	got["second"].Username = "changed"
	fresh := db.GetAll()
	if _, ok := fresh["first"]; !ok {
		t.Error("deleting from the returned map changed the internal map")
	}
	if fresh["second"].Username != "second" {
		t.Error("mutating a returned anchor changed the internal anchor")
	}
}

func TestAnchorsDBFlushClearsInPlace(t *testing.T) {
	db := New()
	db.Add(&AuthPFAnchor{Username: "alice"})

	// Keep a view of the current map to detect replacing it instead of clearing it.
	original := db.data
	db.Flush()

	if len(original) != 0 {
		t.Fatal("Flush left entries in the original map")
	}
	if db.Len() != 0 {
		t.Fatalf("Flush left %d entries in the DB", db.Len())
	}
}

func TestAnchorsDBAddCopiesAnchor(t *testing.T) {
	db := New()
	anchor := &AuthPFAnchor{Username: "alice", Timeout: "1h"}

	db.Add(anchor)
	anchor.Timeout = "0s"

	if got := db.Get("alice").Timeout; got != "1h" {
		t.Fatalf("stored timeout = %q, want %q", got, "1h")
	}
}
