package main

import (
	"context"
	"time"

	"github.com/labstack/echo/v4"
)

func gracefulShutdown(e *echo.Echo) error {
	if config.AuthPF.OnShutdown == "flushall" {
		logger.Info().Msg("Deactivating all active authpf anchors...")
		if err := deactivateAllActiveUsers(); err != nil {
			logger.Error().Err(err).Msg("Error deactivating users")
		}
	}

	// Shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	logger.Info().Msg("Shutting down server...")
	return e.Shutdown(ctx)
}

// deactivateAllActiveUsers removes all active entries from anchorsDB and pfctl
func deactivateAllActiveUsers() error {
	lock.Lock()
	defer lock.Unlock()

	if len(anchorsDB) == 0 {
		logger.Info().Msg("No active authpf anchors found")
		return nil
	}

	logger.Info().Int("count", len(anchorsDB)).Msg("Deactivating authpf anchors")

	// Create and exec pfctl flush for all authpf user rules
	result := unloadAllAuthPFAnchors()
	if result.Error != nil {
		logger.Error().Err(result.Error).Msg("Error unloading pfctl anchors")
		return result.Error
	}

	logger.Info().Msg("All authpf anchors deactivated successfully")
	return nil
}
