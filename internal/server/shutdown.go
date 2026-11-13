package server

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/labstack/echo/v5"
	"github.com/scd-systems/authpf-api/internal/exec"
)

func (s *Server) gracefulShutdown(e *echo.Echo) error {
	// Signal extensions to stop
	s.cancel()

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
	return s.httpServer.Shutdown(ctx)
}

// deactivateAllActiveUsers removes all active entries from anchorsDB and pf tables
func (s *Server) deactivateAllActiveUsers() error {
	lock.Lock()
	defer lock.Unlock()

	if s.db.Len() == 0 {
		s.logger.Info().Msg("No active authpf anchors found")
		return nil
	}

	s.logger.Info().Int("count", s.db.Len()).Msg("Deactivating authpf anchors")
	e, err := exec.New(s.logger, s.config, s.db)
	if err != nil {
		s.logger.Debug().Msgf("Cannot create new Exec: %v", err.Error())
		return err
	}

	// Cleanup pf tables. A failing table delete must never skip the anchor flush
	// below: the anchors are what actually admit traffic, and once this returns
	// the process exits with no session DB left to retry from.
	var tableErr error
	if result := e.FlushAllPFTables(); result != nil {
		tableErr = fmt.Errorf("pf table cleanup incomplete: %w", result.Error)
		s.logger.Error().Err(result.Error).Msg("Error cleanup pf tables")
	} else {
		s.logger.Info().Msg("All pf tables cleaned up successfully")
	}

	s.logger.Info().Msg("All authpf anchors deactivated successfully")
	// Exec pfctl flush for all authpf user rules
	if err = e.FlushAllAnchors("shutdown"); err != nil {
		s.logger.Error().Err(err).Msg("Error unloading authpf anchors")
		return errors.Join(tableErr, err)
	}
	s.logger.Info().Msg("All authpf anchors deactivated successfully")

	return nil
}
