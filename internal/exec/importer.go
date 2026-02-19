package exec

import (
	"bufio"
	"bytes"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/scd-systems/authpf-api/internal/authpf"
	"github.com/scd-systems/authpf-api/internal/validation"
	"github.com/scd-systems/authpf-api/pkg/config"
)

func (e *Exec) ImportAuthPF(db *authpf.AnchorsDB) error {
	args := []string{"-sA"}
	return e.parsePfctlOutput(e.executePfctlCommand(args))
}

// parseExecOutput runs the given command, reads its output and builds a RulesDB.
// Only lines that contain a user‑ID (anchor/username(userID)) are added.
func (e *Exec) parsePfctlOutput(result *SystemCommandResult) error {
	e.logger.Debug().Msg("Start import anchor(s)")

	if result.Error != nil {
		msg := fmt.Sprintf("Failed to import anchor(s): %s", result.Error)
		e.logger.Error().Msg(msg)
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

		// TODO: Check if return error is OK, just skip and continue
		// Validate Username
		if !ValidateUserInConfig(*e.config, username) {
			e.logger.Debug().Msgf("Import: User %s is not configured, anchor ignored", username)
			continue
			// return fmt.Errorf("User already activated")
		}

		// TODO: Check if return error is OK, just skip and continue
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

		e.db.Add(&authpf.AuthPFAnchor{Username: username, UserID: uid, Timeout: e.config.AuthPF.Timeout, ExpiresAt: expiresAt, UserIP: "NaN/imported"})
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
func ValidateTimeout(timeoutStr string) *validation.ValidationError {
	if timeoutStr == "" {
		return &validation.ValidationError{
			HttpStatusCode: http.StatusBadRequest,
			StatusCode:     -1,
			Message:        "Missing timeout validation parameter",
			Details:        fmt.Sprintln("timeout must be a valid duration (e.g., '1h', '30m'), got empty timeout string"),
		}
	}

	d, err := time.ParseDuration(timeoutStr)
	if err != nil {
		return &validation.ValidationError{
			HttpStatusCode: http.StatusBadRequest,
			StatusCode:     -1,
			Message:        "invalid timeout format",
			Details:        fmt.Sprintf("timeout must be a valid duration (e.g., '1h', '30m'), got: %s", timeoutStr),
		}
	}

	if d < time.Minute {
		return &validation.ValidationError{
			HttpStatusCode: http.StatusBadRequest,
			StatusCode:     -1,
			Message:        "timeout must be at least 1 minute",
			Details:        fmt.Sprintf("provided timeout: %v", d),
		}
	}

	if d > 24*time.Hour {
		return &validation.ValidationError{
			HttpStatusCode: http.StatusBadRequest,
			StatusCode:     -1,
			Message:        "timeout cannot exceed 24 hours",
			Details:        fmt.Sprintf("provided timeout: %v", d),
		}
	}
	return nil
}

// Check if user is Configured
func ValidateUserInConfig(config config.ConfigFile, username string) bool {
	if len(username) < 1 {
		return false
	}
	for idx := range config.Rbac.Users {
		if idx == username {
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
