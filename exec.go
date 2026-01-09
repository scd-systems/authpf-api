package main

import (
	"bytes"
	"fmt"
	"os/exec"
	"path"
	"time"
)

func executeSystemCommand(command string, args ...string) *SystemCommandResult {
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

	case <-time.After(30 * time.Second):
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

func executePfctlCommands(commands [][]string) *SystemCommandResult {
	var lastResult *SystemCommandResult

	for _, cmd := range commands {
		lastResult = executePfctlCommand(cmd)
		if lastResult.Error != nil {
			return lastResult
		}
	}
	return lastResult
}

func buildAuthPFRulePath(username string) string {
	const prefix = "/etc/authpf/users"
	const rulesFile = "authpf.rules"
	return path.Join(prefix, username, rulesFile)
}

func buildPfctlCmdParameters(r *AuthPFRule, mode string) []string {
	anchor := fmt.Sprintf("%s/%s", config.AuthPF.AnchorName, r.Username)
	switch mode {
	case AUTHPF_ACTIVATE:
		userIP := fmt.Sprintf("user_ip=%s", r.UserIP)
		userID := fmt.Sprintf("user_id=%d", r.UserID)
		rulePath := buildAuthPFRulePath(r.Username)
		return []string{"-a", anchor, "-D", userIP, "-D", userID, "-f", rulePath}
	case AUTHPF_DEACTIVATE:
		return []string{"-a", anchor, "-Fa"}
	}
	return nil
}

func buildMultiPfctlCmdParameters(r *AuthPFRule, mode string) [][]string {
	anchor := fmt.Sprintf("%s/%s", config.AuthPF.AnchorName, r.Username)
	switch mode {
	case AUTHPF_DEACTIVATE:
		filter := []string{"nat", "queue", "ethernet", "rules", "states", "info", "Sources", "Reset"}
		commands := make([][]string, len(filter))
		for i, f := range filter {
			commands[i] = []string{"-a", anchor, "-F", f}
		}
		return commands
	}
	return nil
}
