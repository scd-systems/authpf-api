package main

import (
	"bufio"
	"bytes"
	"fmt"
	"strconv"
	"strings"
)

func importAuthPF() error {
	args := "-sA"
	return parseAuthpf(*executeSystemCommand(config.Defaults.PfctlBinary, args))
}

// parseExecOutput runs the given command, reads its output and builds a RulesDB.
// Only lines that contain a user‑ID (anchor/username(userID)) are added.
func parseAuthpf(result SystemCommandResult) error {
	logger.Debug().Msg("Start import rules")
	rulesdb = make(map[string]*AuthPFRule)

	if result.Error != nil {
		msg := fmt.Sprintf("Failed to import rules: %s", result.Error)
		logger.Error().Msg(msg)
		return result.Error
	}
	if len(result.Stdout) <= 0 {
		logger.Error().Msg("No rules found to import")
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
		rulesdb[username] = &AuthPFRule{UserID: uid}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	msg := fmt.Sprintf("Imported %d rules", len(rulesdb))
	logger.Debug().Msg(msg)
	return nil
}
