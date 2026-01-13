package main

import (
	"fmt"
	"os"
	"strings"

	yaml "gopkg.in/yaml.v3"
)

func (config *ConfigFile) loadConfig(configFile string) error {
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

	err = yaml.Unmarshal(yamlFile, config)
	if err != nil {
		return fmt.Errorf("cannot parse config file: %v", err)
	}

	// Validate required configuration sections
	if err := config.validateRequiredSections(); err != nil {
		return err
	}

	return nil
}

// validateRequiredSections checks if all required configuration sections are defined
func (config *ConfigFile) validateRequiredSections() error {
	var missingFields []string

	// Check defaults section
	if config.Defaults.Timeout == "" {
		missingFields = append(missingFields, "defaults.timeout")
	}
	if config.Defaults.PfctlBinary == "" {
		missingFields = append(missingFields, "defaults.pfctlBinary")
	}

	// Check server section
	if config.Server.Bind == "" {
		missingFields = append(missingFields, "server.bind")
	}
	if config.Server.Port == 0 {
		missingFields = append(missingFields, "server.port")
	}
	if config.Server.JwtSecret == "" {
		missingFields = append(missingFields, "server.jwtSecret")
	}
	if config.Server.Logfile == "" {
		missingFields = append(missingFields, "server.logfile")
	}
	if config.Server.ElevatorMode == "" {
		missingFields = append(missingFields, "server.elevatorMode")
	}

	// Check authpf section
	if config.AuthPF.UserRulesRootFolder == "" {
		missingFields = append(missingFields, "authpf.userRulesRootFolder")
	}
	if config.AuthPF.UserRulesFile == "" {
		missingFields = append(missingFields, "authpf.userRulesFile")
	}
	if config.AuthPF.AnchorName == "" {
		missingFields = append(missingFields, "authpf.anchorName")
	}

	if len(missingFields) > 0 {
		return fmt.Errorf("missing required configuration fields:\n  - %s", strings.Join(missingFields, "\n  - "))
	}

	return nil
}
