package config

import (
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	yaml "gopkg.in/yaml.v3"
)

// maxTokenTimeout is the longest JWT token timeout accepted from the config.
const maxTokenTimeout = 30 * 24 * time.Hour

// tokenTimeoutPattern matches a whole number with an optional m, h or d unit.
// A missing unit means hours.
var tokenTimeoutPattern = regexp.MustCompile(`^([\d]+)([dhm]?)$`)

func New() *ConfigFile {
	configFile := ConfigFile{}
	return &configFile
}

func (c *ConfigFile) LoadConfig(configFile string) error {
	info, err := os.Stat(configFile)
	if err != nil {
		return fmt.Errorf("cannot access config file: %v", err)
	}

	perms := info.Mode().Perm()
	if perms&0037 != 0 {
		return fmt.Errorf("config file has insecure permissions: %o (should be 0640)", perms)
	}

	yamlFile, err := os.ReadFile(configFile)
	if err != nil {
		return fmt.Errorf("cannot read config file: %v", err)
	}

	err = yaml.Unmarshal(yamlFile, c)
	if err != nil {
		return fmt.Errorf("cannot parse config file: %v", err)
	}

	// Validate Config
	if err := c.validateRequiredSections(); err != nil {
		return err
	}

	return nil
}

// ValidateTokenTimeoutValue converts a token timeout such as "8", "30m", "1h"
// or "2d" into a duration. A value without a unit is read as hours, so "8"
// equals "8h". The result must be longer than zero and at most 30 days.
func ValidateTokenTimeoutValue(timeout string) (time.Duration, error) {
	matches := tokenTimeoutPattern.FindStringSubmatch(strings.TrimSpace(timeout))
	if matches == nil {
		return 0, fmt.Errorf("invalid token timeout %q (expected format: 8, 30m, 1h or 2d)", timeout)
	}

	value, err := strconv.Atoi(matches[1])
	if err != nil {
		return 0, fmt.Errorf("invalid token timeout %q: number out of range", timeout)
	}

	duration := time.Duration(value) * time.Hour
	switch matches[2] {
	case "m":
		duration = time.Duration(value) * time.Minute
	case "d":
		duration = time.Duration(value) * 24 * time.Hour
	}

	if duration == 0 {
		return 0, fmt.Errorf("invalid token timeout %q: must be longer than zero", timeout)
	}

	if duration > maxTokenTimeout {
		return 0, fmt.Errorf("token timeout %q exceeds maximum allowed duration of 30 days", timeout)
	}

	return duration, nil
}

// validateRequiredSections checks if all required configuration sections are defined
func (c *ConfigFile) validateRequiredSections() error {
	var missingFields []string

	// Check defaults section
	if c.Defaults.PfctlBinary == "" {
		missingFields = append(missingFields, "defaults.pfctlBinary")
	}

	// Check server section
	if c.Server.Bind == "" {
		missingFields = append(missingFields, "server.bind")
	}
	if c.Server.Port == 0 {
		missingFields = append(missingFields, "server.port")
	}
	if c.Server.Logfile == "" {
		missingFields = append(missingFields, "server.logfile")
	}
	if c.Server.ElevatorMode == "" {
		missingFields = append(missingFields, "server.elevatorMode")
	}

	// Check authpf section
	if c.AuthPF.Timeout == "" {
		missingFields = append(missingFields, "authpf.timeout")
	}
	if c.AuthPF.UserRulesRootFolder == "" {
		missingFields = append(missingFields, "authpf.userRulesRootFolder")
	}
	if c.AuthPF.UserRulesFile == "" {
		missingFields = append(missingFields, "authpf.userRulesFile")
	}
	if c.AuthPF.AnchorName == "" {
		missingFields = append(missingFields, "authpf.anchorName")
	}
	if len(c.AuthPF.FlushFilter) == 0 {
		missingFields = append(missingFields, "authpf.flushFilter")
	}

	if len(missingFields) > 0 {
		return fmt.Errorf("missing required configuration fields:\n  - %s", strings.Join(missingFields, "\n  - "))
	}

	return nil
}
