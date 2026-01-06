package main

import (
	"time"

	"github.com/rs/zerolog"
)

// startRuleCleaner runs a periodic cleanup of expired authpf rules.
func startRuleCleaner(logger zerolog.Logger) {
	logger.Debug().Msgf("Starting scheduler")
	ticker := time.NewTicker(time.Second * 60)
	defer ticker.Stop()
	for {
		<-ticker.C
		lock.Lock()
		now := time.Now()
		logger.Info().Msgf("Run recurrent authpf rules expire check")
		for id, r := range rules {
			logger.Debug().Msgf("Expire check user: %s, timeout: %s, ExpireAt: %s", r.Username, r.Timeout, r.ExpiresAt)
			if !r.ExpiresAt.IsZero() && now.After(r.ExpiresAt) {
				logger.Info().Msgf("Rule timeout detected, removed authpf rules for user: %s", r.Username)
				delete(rules, id)
				result := unloadAuthPFRule(r.Username)
				logger.Debug().Msgf("Run Command: %s, ExitCode: %d, Stdout: %s, StdErr: %s", result.Command, result.ExitCode, result.Stdout, result.Stderr)
				if result.Error != nil {
					logger.Error().Msgf("Unloading authpf rules failed for user: %s", r.Username)
				}
			}
		}
		lock.Unlock()
	}
}
