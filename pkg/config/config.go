package config

import (
	"bytes"
	"fmt"
	"os"
	"strings"

	yaml "gopkg.in/yaml.v3"
)

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

	// The decoder above drops unknown keys silently, so a misspelled key
	// disables its feature with no error. Collect them here; the caller
	// logs them once the logger exists.
	c.UnknownKeys = collectUnknownKeys(yamlFile)

	// Validate Config
	if err := c.validateRequiredSections(); err != nil {
		return err
	}

	return nil
}

// collectUnknownKeys returns warnings for config keys that match no field in
// ConfigFile. It re-decodes the same bytes with KnownFields(true) and harvests
// the resulting yaml.TypeError, so the key set is derived from the struct tags
// themselves and cannot drift from them. Maps with arbitrary keys (role names,
// usernames, macro names) are accepted by construction.
//
// The caller only reaches this after a successful lenient decode, so any
// remaining messages describe unknown fields rather than type mismatches. The
// filter keeps that true if the two decoders ever diverge.
func collectUnknownKeys(yamlFile []byte) []string {
	var throwaway ConfigFile
	dec := yaml.NewDecoder(bytes.NewReader(yamlFile))
	dec.KnownFields(true)

	err := dec.Decode(&throwaway)
	if err == nil {
		return nil
	}
	typeErr, ok := err.(*yaml.TypeError)
	if !ok {
		return nil
	}

	// The filter is coupled to yaml.v3's wording. If a future version rewords
	// it, warnings would silently disappear rather than misfire, so the tests
	// assert on the message text to make a dependency bump break loudly.
	var unknown []string
	for _, msg := range typeErr.Errors {
		if strings.Contains(msg, "not found in type") {
			unknown = append(unknown, msg)
		}
	}
	return unknown
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
