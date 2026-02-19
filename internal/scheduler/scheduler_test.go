package scheduler

import (
	"os"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/scd-systems/authpf-api/internal/authpf"
	"github.com/stretchr/testify/assert"
)

// TestScheduler_New tests scheduler creation
func TestScheduler_New(t *testing.T) {
	db := authpf.New()
	lock := &sync.Mutex{}
	logger := zerolog.New(os.Stderr)

	scheduler := New(db, lock, logger)

	assert.NotNil(t, scheduler)
	assert.Equal(t, db, scheduler.db)
	assert.Equal(t, lock, scheduler.lock)
}

// TestScheduler_CleanupExpiredRules_NoExpiredRules tests cleanup with no expired rules
func TestScheduler_CleanupExpiredRules_NoExpiredRules(t *testing.T) {
	db := authpf.New()
	lock := &sync.Mutex{}
	logger := zerolog.New(os.Stderr)

	scheduler := New(db, lock, logger)

	// Add a non-expired rule
	futureTime := time.Now().Add(1 * time.Hour)
	anchor := &authpf.AuthPFAnchor{
		Username:  "testuser",
		UserID:    1000,
		UserIP:    "192.168.1.1",
		Timeout:   "1h",
		ExpiresAt: futureTime,
	}
	db.Add(anchor)

	// Run cleanup
	scheduler.cleanupExpiredRules(time.Now())

	// Rule should still be in database
	assert.True(t, db.IsActivated("testuser"))
	assert.Equal(t, 1, len(*db))
}

// TestScheduler_CleanupExpiredRules_WithExpiredRules tests cleanup with expired rules
func TestScheduler_CleanupExpiredRules_WithExpiredRules(t *testing.T) {
	db := authpf.New()
	lock := &sync.Mutex{}
	logger := zerolog.New(os.Stderr)

	scheduler := New(db, lock, logger)

	// Add an expired rule
	pastTime := time.Now().Add(-1 * time.Hour)
	anchor := &authpf.AuthPFAnchor{
		Username:  "testuser",
		UserID:    1000,
		UserIP:    "192.168.1.1",
		Timeout:   "1h",
		ExpiresAt: pastTime,
	}
	db.Add(anchor)

	assert.True(t, db.IsActivated("testuser"))

	// Run cleanup
	scheduler.cleanupExpiredRules(time.Now())

	// Rule should be removed from database
	assert.False(t, db.IsActivated("testuser"))
	assert.Equal(t, 0, len(*db))
}

// TestScheduler_CleanupExpiredRules_MultipleRules tests cleanup with multiple rules
func TestScheduler_CleanupExpiredRules_MultipleRules(t *testing.T) {
	db := authpf.New()
	lock := &sync.Mutex{}
	logger := zerolog.New(os.Stderr)

	scheduler := New(db, lock, logger)

	// Add multiple rules with different expiration times
	pastTime := time.Now().Add(-1 * time.Hour)
	futureTime := time.Now().Add(1 * time.Hour)

	expiredAnchor := &authpf.AuthPFAnchor{
		Username:  "expireduser",
		UserID:    1000,
		UserIP:    "192.168.1.1",
		Timeout:   "1h",
		ExpiresAt: pastTime,
	}

	validAnchor := &authpf.AuthPFAnchor{
		Username:  "validuser",
		UserID:    2000,
		UserIP:    "192.168.1.2",
		Timeout:   "1h",
		ExpiresAt: futureTime,
	}

	db.Add(expiredAnchor)
	db.Add(validAnchor)

	assert.Equal(t, 2, len(*db))

	// Run cleanup
	scheduler.cleanupExpiredRules(time.Now())

	// Only expired rule should be removed
	assert.False(t, db.IsActivated("expireduser"))
	assert.True(t, db.IsActivated("validuser"))
	assert.Equal(t, 1, len(*db))
}

// TestScheduler_CleanupExpiredRules_ZeroExpirationTime tests cleanup with zero expiration time
func TestScheduler_CleanupExpiredRules_ZeroExpirationTime(t *testing.T) {
	db := authpf.New()
	lock := &sync.Mutex{}
	logger := zerolog.New(os.Stderr)

	scheduler := New(db, lock, logger)

	// Add a rule with zero expiration time (should not be cleaned up)
	anchor := &authpf.AuthPFAnchor{
		Username:  "testuser",
		UserID:    1000,
		UserIP:    "192.168.1.1",
		Timeout:   "1h",
		ExpiresAt: time.Time{}, // Zero time
	}
	db.Add(anchor)

	// Run cleanup
	scheduler.cleanupExpiredRules(time.Now())

	// Rule should still be in database
	assert.True(t, db.IsActivated("testuser"))
	assert.Equal(t, 1, len(*db))
}

// TestScheduler_CleanupExpiredRules_ExactExpirationTime tests cleanup at exact expiration time
func TestScheduler_CleanupExpiredRules_ExactExpirationTime(t *testing.T) {
	db := authpf.New()
	lock := &sync.Mutex{}
	logger := zerolog.New(os.Stderr)

	scheduler := New(db, lock, logger)

	// Add a rule that expires at a specific time
	expirationTime := time.Now()
	anchor := &authpf.AuthPFAnchor{
		Username:  "testuser",
		UserID:    1000,
		UserIP:    "192.168.1.1",
		Timeout:   "1h",
		ExpiresAt: expirationTime,
	}
	db.Add(anchor)

	// Run cleanup at exact expiration time (should not be cleaned up because now.After(expiresAt) is false)
	scheduler.cleanupExpiredRules(expirationTime)

	// Rule should still be in database
	assert.True(t, db.IsActivated("testuser"))
	assert.Equal(t, 1, len(*db))
}

// TestScheduler_CleanupExpiredRules_JustAfterExpirationTime tests cleanup just after expiration
func TestScheduler_CleanupExpiredRules_JustAfterExpirationTime(t *testing.T) {
	db := authpf.New()
	lock := &sync.Mutex{}
	logger := zerolog.New(os.Stderr)

	scheduler := New(db, lock, logger)

	// Add a rule that expires at a specific time
	expirationTime := time.Now()
	anchor := &authpf.AuthPFAnchor{
		Username:  "testuser",
		UserID:    1000,
		UserIP:    "192.168.1.1",
		Timeout:   "1h",
		ExpiresAt: expirationTime,
	}
	db.Add(anchor)

	// Run cleanup just after expiration time
	cleanupTime := expirationTime.Add(1 * time.Nanosecond)
	scheduler.cleanupExpiredRules(cleanupTime)

	// Rule should be removed from database
	assert.False(t, db.IsActivated("testuser"))
	assert.Equal(t, 0, len(*db))
}

// TestScheduler_CleanupExpiredRules_EmptyDatabase tests cleanup with empty database
func TestScheduler_CleanupExpiredRules_EmptyDatabase(t *testing.T) {
	db := authpf.New()
	lock := &sync.Mutex{}
	logger := zerolog.New(os.Stderr)

	scheduler := New(db, lock, logger)

	// Run cleanup on empty database
	scheduler.cleanupExpiredRules(time.Now())

	// Database should still be empty
	assert.Equal(t, 0, len(*db))
}

// TestScheduler_CleanupExpiredRules_AllExpired tests cleanup when all rules are expired
func TestScheduler_CleanupExpiredRules_AllExpired(t *testing.T) {
	db := authpf.New()
	lock := &sync.Mutex{}
	logger := zerolog.New(os.Stderr)

	scheduler := New(db, lock, logger)

	// Add multiple expired rules
	pastTime := time.Now().Add(-1 * time.Hour)

	for i := 1; i <= 5; i++ {
		anchor := &authpf.AuthPFAnchor{
			Username:  "user" + string(rune(48+i)),
			UserID:    1000 + i,
			UserIP:    "192.168.1." + string(rune(48+i)),
			Timeout:   "1h",
			ExpiresAt: pastTime,
		}
		db.Add(anchor)
	}

	assert.Equal(t, 5, len(*db))

	// Run cleanup
	scheduler.cleanupExpiredRules(time.Now())

	// All rules should be removed
	assert.Equal(t, 0, len(*db))
}
