package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/rs/zerolog"
)

// startRuleCleaner runs a periodic cleanup of expired authpf anchors.
func startRuleCleaner(logger zerolog.Logger) {
	logger.Debug().Msgf("Authpf scheduler starting")
	ticker := time.NewTicker(time.Second * 60)
	defer ticker.Stop()
	for {
		<-ticker.C
		lock.Lock()
		now := time.Now()
		logger.Trace().Msgf("Run recurrent authpf anchors expire check")
		for _, r := range anchorsDB {
			logger.Trace().Msgf("Expire check user: %s, timeout: %s, ExpireAt: %s", r.Username, r.Timeout, r.ExpiresAt)
			if !r.ExpiresAt.IsZero() && now.After(r.ExpiresAt) {
				logger.Info().Msgf("Rule timeout detected, removed authpf anchors for user: %s", r.Username)
				if err := removeFromAnchorsDB(r.Username, r.UserIP); err != nil {
					logger.Error().Msgf("Unable to remove user: %s from Session DB", r.Username)
				}
				multiResult := unloadAuthPFAnchor(*r)
				for i, result := range multiResult.Results {
					logger.Trace().Msg(fmt.Sprintf("Exec [%d/%d]: '%s %s', ExitCode: %d, Stdout: %s, StdErr: %s",
						i+1, len(multiResult.Results), result.Command, strings.Join(result.Args, " "),
						result.ExitCode, result.Stdout, result.Stderr))
				}
				if multiResult.Error != nil {
					logger.Error().Msgf("Failed to unload authpf anchors from user: %s", r.Username)
				}

			}
		}
		lock.Unlock()
	}
}
