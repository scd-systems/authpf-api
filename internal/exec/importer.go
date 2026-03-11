package exec

import (
	"bufio"
	"bytes"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/scd-systems/authpf-api/internal/authpf"
	"github.com/scd-systems/authpf-api/pkg/config"
)

func (e *Exec) ImportAuthPF() error {
	args := []string{"-sA"}
	return e.parsePfctlOutput(e.executePfctlCommand(args))
}

// parseExecOutput runs the given command, reads its output and builds a RulesDB.
// Only lines that contain a user‑ID (anchor/username(userID)) are added.
func (e *Exec) parsePfctlOutput(result *SystemCommandResult) error {
	e.logger.Debug().Msg("Start import anchor(s)")

	if result.Error != nil {
		e.logger.Error().Err(result.Error).Msg("Failed to import anchor(s)")
		return result.Error
	}
	if len(result.Stdout) <= 0 {
		e.logger.Info().Msg("No anchor(s) found to import")
		return nil
	}

	scanner := bufio.NewScanner(bytes.NewReader([]byte(result.Stdout)))

	for scanner.Scan() {
		line := scanner.Text()

		// Split /
		parts := strings.SplitN(line, "/", 2)
		if len(parts) != 2 {
			continue
		}
		rest := parts[1]

		// check for brackets
		openIdx := strings.Index(rest, "(")
		closeIdx := strings.LastIndex(rest, ")")
		if openIdx == -1 || closeIdx == -1 || closeIdx <= openIdx+1 {
			continue
		}

		username := rest[:openIdx]

		idStr := rest[openIdx+1 : closeIdx]
		uid, err := strconv.Atoi(idStr)
		if err != nil {
			continue
		}

		// Validate Username and UserID
		if !validateUserAndIDConfig(e.config, username, uid) {
			e.logger.Debug().Msgf("Import: Username %s and/or UserID %d does not match configuration, anchor ignored", username, uid)
			continue
		}

		// Validate if Username already activated
		if e.db.IsActivated(username) {
			e.logger.Debug().Msgf("Import: Anchor for user %s already activated", username)
			continue
		}

		// Check configure Timeout Variable
		if err := ValidateTimeout(e.config.AuthPF.Timeout); err != nil {
			return err
		}
		// Calculate the ExpireAt Timeout
		expiresAt, err := CalculateAnchorExpire(e.config.AuthPF.Timeout)
		if err != nil {
			return err
		}

		anchor, err := authpf.SetAnchor(username, e.config.AuthPF.Timeout, "NaN/imported", uid, expiresAt)
		if err != nil {
			return err
		}
		e.db.Add(anchor)
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	if len(*e.db) > 0 {
		for _, v := range *e.db {
			msg := fmt.Sprintf("Anchor: %s/%s(%d) imported, ExpireAt: %s", e.config.AuthPF.AnchorName, v.Username, v.UserID, v.ExpiresAt)
			e.logger.Trace().Msg(msg)
		}
	}
	e.logger.Debug().Int("count", len(*e.db)).Msg("Import anchor(s) done")
	return nil
}

// Check for valid AuthPF Timeout string
func ValidateTimeout(timeoutStr string) error {
	if timeoutStr == "" {
		return fmt.Errorf("missing timeout validation parameter, timeout must be a valid duration (e.g., '1h', '30m'), got empty timeout string")
	}

	d, err := time.ParseDuration(timeoutStr)
	if err != nil {
		return fmt.Errorf("invalid timeout format, timeout must be a valid duration (e.g., '1h', '30m'), got: %s", timeoutStr)
	}

	if d < time.Minute {
		return fmt.Errorf("timeout must be at least 1 minute, provided timeout: %v", d)
	}

	if d > 24*time.Hour {
		return fmt.Errorf("timeout cannot exceed 24 hours, provided timeout: %v", d)
	}
	return nil
}

// Check UserID
func validateUserAndIDConfig(config *config.ConfigFile, username string, userid int) bool {
	for idx, v := range config.Rbac.Users {
		if idx == username && v.UserID == userid {
			return true
		}
	}
	return false
}

// Add timeout to current time from server as Expire Date
func CalculateAnchorExpire(timeoutStr string) (time.Time, error) {
	d, err := time.ParseDuration(timeoutStr)
	if err != nil {
		return time.Time{}, err
	}
	return time.Now().Add(d), nil
}
