package scheduler

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"github.com/scd-systems/authpf-api/internal/authpf"
	"github.com/scd-systems/authpf-api/internal/exec"
	"github.com/scd-systems/authpf-api/pkg/config"
)

type Scheduler struct {
	db     *authpf.AnchorsDB
	lock   *sync.Mutex
	logger zerolog.Logger
	config config.ConfigFile
}

func New(db *authpf.AnchorsDB, lock *sync.Mutex, logger zerolog.Logger) *Scheduler {
	return &Scheduler{db: db, lock: lock, logger: logger}
}

// cleanupExpiredRules checks and removes expired authpf anchors from the database.
// This function must be called with the lock already held.
func (s *Scheduler) cleanupExpiredRules(now time.Time) {
	s.logger.Trace().Msgf("Run recurrent authpf anchors expire check")

	// Create a list of expired rules to avoid modifying map during iteration
	var expiredRules []*authpf.AuthPFAnchor
	for _, r := range *s.db {
		s.logger.Trace().Msgf("Expire check user: %s, timeout: %s, ExpireAt: %s", r.Username, r.Timeout, r.ExpiresAt)
		if !r.ExpiresAt.IsZero() && now.After(r.ExpiresAt) {
			expiredRules = append(expiredRules, r)
		}
	}

	// Process expired rules
	for _, r := range expiredRules {
		s.logger.Info().Msgf("Rule timeout detected, removed authpf anchors for user: %s", r.Username)
		if err := s.db.Remove(r.Username); err != nil {
			s.logger.Error().Msgf("Unable to remove user: %s from Session DB", r.Username)
		}
		e := exec.New(s.logger, &s.config, s.db)
		multiResult := e.UnloadAuthPFAnchor(r)
		for i, result := range multiResult.Results {
			s.logger.Trace().Msg(fmt.Sprintf("Exec [%d/%d]: '%s %s', ExitCode: %d, Stdout: %s, StdErr: %s",
				i+1, len(multiResult.Results), result.Command, strings.Join(result.Args, " "),
				result.ExitCode, result.Stdout, result.Stderr))
		}
		if multiResult.Error != nil {
			s.logger.Error().Msgf("Failed to unload authpf anchors from user: %s", r.Username)
		}
	}
}

// Scheduler runs a periodic cleanup of expired authpf anchors.
func (s *Scheduler) Run() {
	s.logger.Debug().Msgf("Authpf scheduler starting")
	ticker := time.NewTicker(time.Second * 60)
	defer ticker.Stop()
	for {
		<-ticker.C
		s.lock.Lock()
		s.cleanupExpiredRules(time.Now())
		s.lock.Unlock()
	}
}
