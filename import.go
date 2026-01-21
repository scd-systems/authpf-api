package main

import (
	"bufio"
	"bytes"
	"fmt"
	"strconv"
	"strings"
)

func importAuthPF() error {
	args := []string{"-sA"}
	return parseAuthpf(*executePfctlCommand(args))
}

// parseExecOutput runs the given command, reads its output and builds a RulesDB.
// Only lines that contain a user‑ID (anchor/username(userID)) are added.
func parseAuthpf(result SystemCommandResult) error {
	logger.Debug().Msg("Start import anchor(s)")
	rulesdb = make(map[string]*AuthPFRule)

	if result.Error != nil {
		msg := fmt.Sprintf("Failed to import anchor(s): %s", result.Error)
		logger.Error().Msg(msg)
		return result.Error
	}
	if len(result.Stdout) <= 0 {
		logger.Error().Msg("No anchor(s) found to import")
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
		timeout, expiresAt, valErr := ValidateTimeout(config.AuthPF.Timeout)
		if valErr != nil {
			return valErr
		}

		rulesdb[username] = &AuthPFRule{Username: username, UserID: uid, Timeout: timeout, ExpiresAt: expiresAt, UserIP: "NaN/imported"}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	if len(rulesdb) > 0 {
		for _, v := range rulesdb {
			msg := fmt.Sprintf("Anchor: %s/%s(%d) imported, ExpireAt: %s", config.AuthPF.AnchorName, v.Username, v.UserID, v.ExpiresAt)
			logger.Trace().Msg(msg)
		}
	}
	logger.Debug().Int("count", len(rulesdb)).Msg("Import anchor(s) done")
	return nil
}
