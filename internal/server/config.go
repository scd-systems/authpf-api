package server

import (
	"github.com/scd-systems/authpf-api/pkg/config"
)

// validateConfig applies the config file's own rules, then turns the one value
// that is impractical rather than wrong into a warning: a scheduler interval
// that keeps expired anchors active well past their own timeout.
//
// The rules themselves live in pkg/config/config_validate.go, next to the types
// they describe, so that anything reading a config file gets the same answers
// without importing this package. What stays here is the part that needs this
// process: a logger to warn on, and the decision to abort (bootstrap.go turns a
// returned error into log.Fatalf).
//
// The warning is emitted after the fatal checks, so a configuration that does
// not start up at all is reported as an error and not as a warning.
func (s *Server) validateConfig() error {
	if err := s.config.Validate(); err != nil {
		return err
	}

	interval, err := config.ValidateSchedulerInterval(s.config.AuthPF.SchedulerInterval)
	if err != nil {
		return err
	}
	if interval > config.SchedulerIntervalWarnThreshold {
		s.logger.Warn().Msgf("⚠️ authpf.schedulerInterval is %s: expired anchors are only removed on the next loop, so they stay active up to %s past their own timeout", interval, interval)
	}

	return nil
}
