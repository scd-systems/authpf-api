package main

import (
	"bytes"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/labstack/gommon/log"
)

func executeSystemCommand(command string, args ...string) *SystemCommandResult {
	const commandExecutionTimeout = 30 * time.Second

	cmd := exec.Command(command, args...)

	// Capture stdout and stderr
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	// Execute command with timeout
	done := make(chan error, 1)
	go func() {
		done <- cmd.Run()
	}()

	// Wait for command with 30 second timeout
	select {
	case err := <-done:
		exitCode := 0

		if err != nil {
			if exitErr, ok := err.(*exec.ExitError); ok {
				exitCode = exitErr.ExitCode()
			} else {
				// Return -1 and error if exec cannot run
				exitCode = -1
				stderr.WriteString(err.Error())
			}
		}

		return &SystemCommandResult{
			Command:  command,
			Args:     args,
			Stdout:   stdout.String(),
			Stderr:   stderr.String(),
			ExitCode: exitCode,
			Error:    err,
		}
	case <-time.After(commandExecutionTimeout):
		cmd.Process.Kill()
		return &SystemCommandResult{
			Command:  command,
			Args:     args,
			Stdout:   stdout.String(),
			Stderr:   stderr.String(),
			ExitCode: -1,
			Error:    fmt.Errorf("command execution timeout (30s)"),
		}
	}
}

func buildPfctlCmd() string {
	prefix := config.Defaults.PfctlBinary
	switch config.Server.ElevatorMode {
	case "sudo":
		prefix = "sudo"
	case "doas":
		prefix = "doas"
	}
	return prefix
}

func executePfctlCommand(cmd []string) *SystemCommandResult {
	prefix := buildPfctlCmd()
	args := cmd
	if prefix != config.Defaults.PfctlBinary {
		args = append([]string{config.Defaults.PfctlBinary}, cmd...)
	}
	return executeSystemCommand(prefix, args...)
}

func executePfctlCommands(commands [][]string) *MultiCommandResult {
	results := make([]*SystemCommandResult, 0)

	for _, cmd := range commands {
		result := executePfctlCommand(cmd)
		results = append(results, result)
		if result.Error != nil {
			return &MultiCommandResult{
				Results: results,
				Error:   result.Error,
			}
		}
	}
	return &MultiCommandResult{
		Results: results,
		Error:   nil,
	}
}

func buildAuthPFRulePath(username string) (string, error) {
	if err := config.validateUsername(username); err != nil {
		return "", err
	}

	basePath := config.AuthPF.UserRulesRootFolder
	rulePath := filepath.Join(basePath, username, config.AuthPF.UserRulesFile)

	absBase, err := filepath.Abs(basePath)
	if err != nil {
		return "", fmt.Errorf("invalid base path: %v", err)
	}

	absRule, err := filepath.Abs(rulePath)
	if err != nil {
		return "", fmt.Errorf("invalid rule path: %v", err)
	}

	if !strings.HasPrefix(absRule, absBase) {
		return "", fmt.Errorf("path traversal detected: %s", rulePath)
	}

	return rulePath, nil
}

func buildPfctlActivateCmdParameters(r *AuthPFRule) []string {
	anchor := fmt.Sprintf("%s/%s(%d)", config.AuthPF.AnchorName, r.Username, r.UserID)
	userIP := fmt.Sprintf("user_ip=%s", r.UserIP)
	if valErr := ValidateUserIP(r.UserIP); valErr != nil {
		log.Errorf(valErr.Error())
		return []string{}
	}
	userID := fmt.Sprintf("user_id=%d", r.UserID)
	rulePath, err := buildAuthPFRulePath(r.Username)
	if err != nil {
		log.Errorf(err.Error())
		return []string{}
	}
	return []string{"-a", anchor, "-D", userIP, "-D", userID, "-f", rulePath}
}

func buildPfctlDeactivateCmdParameters(r *AuthPFRule) [][]string {
	anchor := fmt.Sprintf("%s/%s(%d)", config.AuthPF.AnchorName, r.Username, r.UserID)

	filter := config.AuthPF.FlushFilter
	if len(filter) < 1 {
		filter = []string{"rules", "nat"}
	}
	commands := make([][]string, len(filter))
	for i, f := range filter {
		commands[i] = []string{"-a", anchor, "-F", f}
	}
	return commands
}

func buildPfctlDeactivateAllCmdParameters() [][]string {
	filter := config.AuthPF.FlushFilter
	if len(filter) < 1 {
		filter = []string{"rules", "nat"}
	}

	commands := make([][]string, 0)

	// Iterate over all users in rulesdb
	for _, v := range rulesdb {
		anchor := fmt.Sprintf("%s/%s(%d)", config.AuthPF.AnchorName, v.Username, v.UserID)
		for _, f := range filter {
			commands = append(commands, []string{"-a", anchor, "-F", f})
		}
	}

	return commands
}
