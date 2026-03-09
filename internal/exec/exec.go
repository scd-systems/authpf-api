package exec

import (
	"bytes"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"github.com/scd-systems/authpf-api/internal/authpf"
	"github.com/scd-systems/authpf-api/pkg/config"
)

type Exec struct {
	config *config.ConfigFile
	db     *authpf.AnchorsDB
	logger zerolog.Logger
}

type SystemCommandResult struct {
	Command  string
	Args     []string
	Stdout   string
	Stderr   string
	ExitCode int
	Error    error
}

type MultiCommandResult struct {
	Results []*SystemCommandResult
	Error   error
}

func New(logger zerolog.Logger, config *config.ConfigFile, db *authpf.AnchorsDB) *Exec {
	return &Exec{logger: logger, config: config, db: db}
}

func NewNoConfig(logger zerolog.Logger, db *authpf.AnchorsDB) *Exec {
	return &Exec{logger: logger, db: db}
}

func (e *Exec) executeSystemCommand(command string, args ...string) *SystemCommandResult {
	const commandExecutionTimeout = 30 * time.Second

	msg := fmt.Sprintf("Running command: %s %s", command, args)
	e.logger.Trace().Msg(msg)

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
		if err := cmd.Process.Kill(); err != nil {
			e.logger.Error().Msg(fmt.Sprintf("Cannot kill process: %s", err))
		}
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

func (e *Exec) buildPfctlCmd() string {
	prefix := e.config.Defaults.PfctlBinary
	switch e.config.Server.ElevatorMode {
	case "sudo":
		prefix = "sudo"
	case "doas":
		prefix = "doas"
	}
	return prefix
}

func (e *Exec) executePfctlCommand(cmd []string) *SystemCommandResult {
	prefix := e.buildPfctlCmd()
	args := cmd
	if prefix != e.config.Defaults.PfctlBinary {
		args = append([]string{e.config.Defaults.PfctlBinary}, cmd...)
	}
	return e.executeSystemCommand(prefix, args...)
}

func (e *Exec) executePfctlCommands(commands [][]string) *MultiCommandResult {
	results := make([]*SystemCommandResult, 0)

	for _, cmd := range commands {
		result := e.executePfctlCommand(cmd)
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

func (e *Exec) buildAuthPFAnchorPath(username string) (string, error) {
	basePath := e.config.AuthPF.UserRulesRootFolder
	rulePath := filepath.Join(basePath, username, e.config.AuthPF.UserRulesFile)

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

func (e *Exec) buildPfctlActivateCmdParameters(r *authpf.AuthPFAnchor) []string {
	anchor := fmt.Sprintf("%s/%s(%d)", e.config.AuthPF.AnchorName, r.Username, r.UserID)

	userIP := fmt.Sprintf("user_ip=%s", r.UserIP)
	userID := fmt.Sprintf("user_id=%d", r.UserID)

	rulePath, err := e.buildAuthPFAnchorPath(r.Username)
	if err != nil {
		e.logger.Error().Msg(err.Error())
		return []string{}
	}

	params := []string{"-a", anchor, "-D", userIP, "-D", userID}

	// Append user-defined macros from RBAC config as -D key=value
	if user, ok := e.config.Rbac.Users[r.Username]; ok {
		for k, v := range user.Macros {
			params = append(params, "-D", fmt.Sprintf("%s=%v", k, v))
		}
	}

	params = append(params, "-f", rulePath)
	return params
}

func (e *Exec) buildPfctlDeactivateCmdParameters(r *authpf.AuthPFAnchor) [][]string {
	anchor := fmt.Sprintf("%s/%s(%d)", e.config.AuthPF.AnchorName, r.Username, r.UserID)

	filter := e.config.AuthPF.FlushFilter
	if len(filter) < 1 {
		filter = []string{"rules", "nat"}
	}
	commands := make([][]string, len(filter))
	for i, f := range filter {
		commands[i] = []string{"-a", anchor, "-F", f}
	}
	return commands
}

func (e *Exec) buildPfctlDeactivateAllCmdParameters() [][]string {
	filter := e.config.AuthPF.FlushFilter
	if len(filter) < 1 {
		filter = []string{"rules", "nat"}
	}

	commands := make([][]string, 0)

	// Iterate over all users in anchorsDB
	for _, v := range *e.db {
		anchor := fmt.Sprintf("%s/%s(%d)", e.config.AuthPF.AnchorName, v.Username, v.UserID)
		for _, f := range filter {
			commands = append(commands, []string{"-a", anchor, "-F", f})
		}
	}

	return commands
}

// Run Load AuthPF Anchor
func (e *Exec) LoadAuthPFAnchor(r *authpf.AuthPFAnchor) *SystemCommandResult {
	parameters := e.buildPfctlActivateCmdParameters(r)
	return e.executePfctlCommand(parameters)
}

// Run Unload AuthPF Anchor
func (e *Exec) UnloadAuthPFAnchor(r *authpf.AuthPFAnchor) *MultiCommandResult {
	parameters := e.buildPfctlDeactivateCmdParameters(r)
	return e.executePfctlCommands(parameters)
}

// Run Unload ALL AuthPF Rules
func (e *Exec) UnloadAllAuthPFAnchors() *MultiCommandResult {
	parameters := e.buildPfctlDeactivateAllCmdParameters()
	return e.executePfctlCommands(parameters)
}

func (e *Exec) ExecUnloadAllAuthPFAnchors(username string, logger *zerolog.Logger, config config.ConfigFile) error {
	if len(*e.db) < 1 {
		e.logger.Debug().Msg("No anchors to flush")
		return nil
	}

	msg := fmt.Sprintf("Found %d user anchors to flush", len(*e.db))
	e.logger.Debug().Msg(msg)

	multiResult := e.UnloadAllAuthPFAnchors()

	// Log all commands
	for i, result := range multiResult.Results {
		msg := fmt.Sprintf("Exec [%d/%d]: '%s %s', ExitCode: %d, Stdout: %s, StdErr: %s",
			i+1, len(multiResult.Results), result.Command, strings.Join(result.Args, " "),
			result.ExitCode, result.Stdout, result.Stderr)
		e.logger.Debug().Str("user", username).Msg(msg)
	}

	if multiResult.Error != nil {
		msg := fmt.Sprintf("unload all authpf anchors failed: %s", multiResult.Error)
		e.logger.Debug().Str("user", username).Msg(msg)
		return multiResult.Error
	}
	e.db = authpf.New()
	e.logger.Debug().Msg("Flushing anchors succeed")
	return nil
}

// Resolve PF Table (user/global)
// TODO: check were to skip if not defined
func (e *Exec) resolvePfTable(username string) string {
	if user, ok := e.config.Rbac.Users[username]; ok && user.PfTable != "" {
		return user.PfTable
	}
	return e.config.AuthPF.PfTable
}

func (e *Exec) AddIPToPfTable(r *authpf.AuthPFAnchor) *SystemCommandResult {
	table := e.resolvePfTable(r.Username)
	if table == "" {
		return nil
	}
	return e.executePfctlCommand([]string{"-t", table, "-T", "add", r.UserIP})
}

func (e *Exec) RemoveIPFromPfTable(r *authpf.AuthPFAnchor) *SystemCommandResult {
	table := e.resolvePfTable(r.Username)
	if table == "" {
		return nil
	}
	return e.executePfctlCommand([]string{"-t", table, "-T", "delete", r.UserIP})
}

func (e *Exec) RemoveAllIPsFromPfTable() {
	for _, anchor := range *e.db {
		result := e.RemoveIPFromPfTable(anchor)
		if result != nil && result.ExitCode != 0 {
			e.logger.Warn().Str("user", anchor.Username).
				Msgf("failed to remove IP %s from pf table: %s", anchor.UserIP, result.Stderr)
		}
	}
}

func (e *Exec) CheckPfTableExists(tableName string) error {
	result := e.executePfctlCommand([]string{"-t", tableName, "-T", "show"})
	if result.ExitCode != 0 {
		return fmt.Errorf("pf table %q does not exist or is not accessible: %s", tableName, result.Stderr)
	}
	return nil
}
