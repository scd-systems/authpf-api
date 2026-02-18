package server

import (
	"context"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/scd-systems/authpf-api/internal/exec"
)

func (s *Server) gracefulShutdown(e *echo.Echo) error {
	if s.config.AuthPF.OnShutdown == "flushall" {
		s.logger.Info().Msg("Deactivating all active authpf anchors...")
		if err := s.deactivateAllActiveUsers(); err != nil {
			s.logger.Error().Err(err).Msg("Error deactivating users")
		}
	}

	// Shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	s.logger.Info().Msg("Shutting down server...")
	return e.Shutdown(ctx)
}

// deactivateAllActiveUsers removes all active entries from anchorsDB and pfctl
func (s *Server) deactivateAllActiveUsers() error {
	lock.Lock()
	defer lock.Unlock()

	if len(*s.db) == 0 {
		s.logger.Info().Msg("No active authpf anchors found")
		return nil
	}

	s.logger.Info().Int("count", len(*s.db)).Msg("Deactivating authpf anchors")

	e := exec.New(s.logger, s.config, s.db)
	// Create and exec pfctl flush for all authpf user rules
	result := e.UnloadAllAuthPFAnchors()
	if result.Error != nil {
		s.logger.Error().Err(result.Error).Msg("Error unloading pfctl anchors")
		return result.Error
	}

	s.logger.Info().Msg("All authpf anchors deactivated successfully")
	return nil
}
