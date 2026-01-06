package main

import (
	"bytes"
	"fmt"
	"os/exec"
	"path"
	"strings"
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

// func reloadPF(c echo.Context) error {
// 	result := executeSystemCommand("ls", "-la")
// 	if result.Error != nil {
// 		c.Logger().Errorf("pfctl failed: %v", result.Error)
// 		return c.JSON(http.StatusInternalServerError, echo.Map{"error": "pfctl execution failed"})
// 	}
// 	return c.JSON(http.StatusOK, echo.Map{"status": result.Stdout})
// }

func buildPfctlCmd() string {
	prefix := ""
	switch config.Server.ElevatorMode {
	case "sudo":
		prefix = "sudo"
	case "doas":
		prefix = "doas"
	}
	pfCtl := strings.TrimSpace(fmt.Sprintf("%s %s", prefix, config.Defaults.PfctlBinary))
	return pfCtl
}

func executePfctlCommand(cmd []string) *SystemCommandResult {
	pfCtl := buildPfctlCmd()
	return executeSystemCommand(pfCtl, cmd...)
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
		clientIP := fmt.Sprintf("client_ip=%s", r.ClientIP)
		clientID := fmt.Sprintf("client_id=%d", r.ClientID)
		rulePath := buildAuthPFRulePath(r.Username)
		return []string{"-a", anchor, "-D", clientIP, "-D", clientID, "-f", rulePath}
	case AUTHPF_DEACTIVATE:
		return []string{"-a", anchor, "-Fa"}
	}
	return nil
}
