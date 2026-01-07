package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/rs/zerolog"
)

// startRuleCleaner runs a periodic cleanup of expired authpf rules.
func startRuleCleaner(logger zerolog.Logger) {
	logger.Debug().Msgf("Authpf scheduler starting")
	ticker := time.NewTicker(time.Second * 60)
	var msg string
	defer ticker.Stop()
	for {
		<-ticker.C
		lock.Lock()
		now := time.Now()
		logger.Debug().Msgf("Run recurrent authpf rules expire check")
		for id, r := range rulesdb {
			logger.Debug().Msgf("Expire check user: %s, timeout: %s, ExpireAt: %s", r.Username, r.Timeout, r.ExpiresAt)
			if !r.ExpiresAt.IsZero() && now.After(r.ExpiresAt) {
				logger.Info().Msgf("Rule timeout detected, removed authpf rules for user: %s", r.Username)
				delete(rulesdb, id)
				result := unloadAuthPFRule(r.Username)
				msg = fmt.Sprintf("Exec: '%s %s', ExitCode: %d, Stdout: %s, StdErr: %s", result.Command, strings.Join(result.Args, " "), result.ExitCode, result.Stdout, result.Stderr)
				logger.Debug().Msgf(msg)
				if result.Error != nil {
					logger.Error().Msgf("Unloading authpf rules failed for user: %s", r.Username)
				}
			}
		}
		lock.Unlock()
	}
}
