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

// minJwtSecretLength is the minimum length of JWT Secret in configuration
const minJwtSecretLength = 32

// DefaultSchedulerInterval is the scheduler loop interval used when
// authpf.schedulerInterval is empty.
const DefaultSchedulerInterval = 60 * time.Second

// minSchedulerInterval is how often the scheduler may at most take the session
// DB lock and shell out to pfctl. Anything below a second only spins.
const minSchedulerInterval = time.Second

// maxSchedulerInterval is the longest accepted loop interval, mirroring the
// bound on the JWT token timeout. Above it, expired anchors would effectively
// never be revoked again.
const maxSchedulerInterval = 30 * 24 * time.Hour

// SchedulerIntervalWarnThreshold is the point where the operator is warned
// without the value being rejected: an anchor stays active up to one full
// interval past its own timeout, so a long loop makes revocations late.
const SchedulerIntervalWarnThreshold = 30 * time.Minute

// schedulerSecondsPattern matches the bare number form documented in README.md
// and authpf-api.conf.sample, where schedulerInterval: 60 means 60 seconds.
var schedulerSecondsPattern = regexp.MustCompile(`^[\d]+$`)

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

// ValidateSchedulerInterval converts authpf.schedulerInterval into a duration.
// A bare number is read as seconds, the format the docs and the config sample
// use; anything else must be a Go duration such as "90s" or "2m". An empty
// value selects the default. Values below one second are rejected: a
// non-positive interval makes time.NewTicker panic in the scheduler goroutine,
// and a fractional one truncated to zero seconds does the same. Values above
// 30 days are rejected, see maxSchedulerInterval.
func ValidateSchedulerInterval(value string) (time.Duration, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return DefaultSchedulerInterval, nil
	}
	if schedulerSecondsPattern.MatchString(trimmed) {
		trimmed += "s"
	}

	duration, err := time.ParseDuration(trimmed)
	if err != nil {
		return 0, fmt.Errorf("invalid authpf.schedulerInterval %q (expected seconds like 60, or a duration like 90s)", value)
	}
	if duration < minSchedulerInterval {
		return 0, fmt.Errorf("authpf.schedulerInterval %q is below the minimum of 1s", value)
	}
	if duration > maxSchedulerInterval {
		return 0, fmt.Errorf("authpf.schedulerInterval %q exceeds the maximum of 30 days", value)
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

	if c.Server.JwtSecret != "" {
		if strings.TrimSpace(c.Server.JwtSecret) == "" {
			return fmt.Errorf("server.jwtSecret is set but contains only whitespace")
		}
		if len(c.Server.JwtSecret) < minJwtSecretLength {
			return fmt.Errorf("server.jwtSecret must be at least %d characters, got %d", minJwtSecretLength, len(c.Server.JwtSecret))
		}
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
