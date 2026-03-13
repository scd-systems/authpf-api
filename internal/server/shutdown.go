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

// deactivateAllActiveUsers removes all active entries from anchorsDB and pf tables
func (s *Server) deactivateAllActiveUsers() error {
	lock.Lock()
	defer lock.Unlock()

	if len(*s.db) == 0 {
		s.logger.Info().Msg("No active authpf anchors found")
		return nil
	}

	s.logger.Info().Int("count", len(*s.db)).Msg("Deactivating authpf anchors")
	e, err := exec.New(s.logger, s.config, s.db)
	if err != nil {
		s.logger.Debug().Msgf("Cannot create new Exec: %v", err.Error())
		return err
	}

	// Cleanup pf tables
	if result := e.FlushAllPFTables(); result != nil {
		s.logger.Error().Err(result.Error).Msg("Error cleanup pf tables")
		return result.Error
	}
	s.logger.Info().Msg("All pf tables cleaned up successfully")

	// Exec pfctl flush for all authpf user rules
	if err = e.FlushAllAnchors("shutdown"); err != nil {
		s.logger.Error().Err(err).Msg("Error unloading authpf anchors")
		return err
	}
	s.logger.Info().Msg("All authpf anchors deactivated successfully")

	return nil
}
