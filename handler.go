package main

import (
	"bytes"
	"fmt"
	"net/http"
	"os/exec"
	"path"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
)

// loadAuthPFRule handles POST /api/v1/authpf/activate
func loadAuthPFRule(c echo.Context) error {
	lock.Lock()
	defer lock.Unlock()

	timeoutStr := c.QueryParam("timeout")
	if timeoutStr == "" {
		timeoutStr = "30m"
	}

	r := &AuthPFRule{
		Timeout: timeoutStr,
	}

	if timeoutStr != "" {
		if d, err := time.ParseDuration(timeoutStr); err == nil {
			r.ExpiresAt = time.Now().Add(d)
		}
	}

	if err := c.Bind(r); err != nil {
		return c.JSON(http.StatusBadRequest, echo.Map{"error": "invalid JSON payload"})
	}

	r.ClientIP = c.RealIP()
	username, ok := c.Get("username").(string)
	if !ok {
		return c.JSON(http.StatusUnauthorized, echo.Map{"error": "invalid username in token"})
	}
	r.Username = username

	for _, v := range rules {
		if v.Username == r.Username {
			c.Logger().Infof("Loading authpf failed")
			return c.JSON(http.StatusMethodNotAllowed, echo.Map{"error": "authpf rule for user already activated"})
		}
	}

	rules[r.Username] = r

	rulePath := buildAuthPFRulePath(r.Username)
	fullPath := path.Join(rulePath...)
	authPfCommand := buildAuthPFCmd(r, fullPath)

	// Check permission
	if err := config.validateUserPermissions(r.Username, RBAC_ACTIVATE_RULE); err != nil {
		c.Logger().Infof(err.Error())
		return c.JSON(http.StatusForbidden, echo.Map{"status": "rejected", "msg": err.Error()})
	}

	if _, err := loadPfRule(c, authPfCommand); err != nil {
		c.Logger().Errorf("Loading authpf rules failed for user: %s", r.Username)
		return c.JSON(http.StatusInternalServerError, echo.Map{"status": "failed", "msg": "authpf rule not loaded"})
	}
	c.Logger().Infof("Loading authpf rule user=%s with timeout=%s, ExpireAt=%s", r.Username, r.Timeout, r.ExpiresAt)
	return c.JSON(http.StatusAccepted, echo.Map{"status": "queued", "user": r.Username, "msg": "authpf rule is being loaded"})
}

// getLoadAuthPFRules handles GET /api/v1/authpf/rules
func getLoadAuthPFRules(c echo.Context) error {
	lock.Lock()
	defer lock.Unlock()
	return c.JSON(http.StatusOK, rules)
}

// deleteAllAuthPFRules handles DELETE /api/v1/authpf/all
func deleteAllAuthPFRules(c echo.Context) error {
	lock.Lock()
	defer lock.Unlock()
	rules = make(map[string]*AuthPFRule)
	return c.JSON(http.StatusOK, echo.Map{"status": "cleared"})
}

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
			}
		}

		return &SystemCommandResult{
			Command:  command,
			Stdout:   stdout.String(),
			Stderr:   stderr.String(),
			ExitCode: exitCode,
			Error:    err,
		}

	case <-time.After(30 * time.Second):
		cmd.Process.Kill()
		return &SystemCommandResult{
			Command:  command,
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

func loadPfRule(c echo.Context, cmd []string) (string, error) {
	prefix := ""
	switch config.Server.ElevatorMode {
	case "sudo":
		prefix = "sudo"
	case "doas":
		prefix = "doas"
	}
	pfCtl := strings.TrimSpace(fmt.Sprintf("%s %s", prefix, config.Defaults.PfctlBinary))
	result := executeSystemCommand(pfCtl, cmd...)
	if result.Error != nil {
		c.Logger().Errorf("Failed: %v", result.Error)
		return result.Stdout, result.Error
	}
	return result.Stdout, nil
}

func buildAuthPFRulePath(username string) []string {
	const prefix = "/etc/authpf/users"
	const rulesFile = "authpf.rules"
	return []string{prefix, username, rulesFile}
}

func buildAuthPFCmd(r *AuthPFRule, path string) []string {
	clientIP := fmt.Sprintf("client_ip=%s", r.ClientIP)
	clientID := fmt.Sprintf("client_id=%d", r.ClientID)
	return []string{"-a", "authpf/user", "-D", clientIP, "-D", clientID, "-f", path}
}
