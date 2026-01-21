package main

import (
	"context"
	"time"

	"github.com/labstack/echo/v4"
)

func gracefulShutdown(e *echo.Echo) error {
	logger.Info().Msg("Deactivating all active authpf rules...")

	if config.AuthPF.OnShutdown == "flushall" {
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

// deactivateAllActiveUsers removes all active rules from anchorsDB and pfctl
func deactivateAllActiveUsers() error {
	lock.Lock()
	defer lock.Unlock()

	if len(anchorsDB) == 0 {
		logger.Info().Msg("No active authpf rules found")
		return nil
	}

	logger.Info().Int("count", len(anchorsDB)).Msg("Deactivating authpf rules")

	// Create and exec pfctl flush for all authpf user rules
	result := unloadAllAuthPFRule()
	if result.Error != nil {
		logger.Error().Err(result.Error).Msg("Error unloading pfctl rules")
		return result.Error
	}

	logger.Info().Msg("All authpf rules deactivated successfully")
	return nil
}
