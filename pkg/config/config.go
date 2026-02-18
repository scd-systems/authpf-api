package config

import (
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

	// Validate Config
	if err := c.validateRequiredSections(); err != nil {
		return err
	}

	return nil
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
