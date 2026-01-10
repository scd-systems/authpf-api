package main

import (
	"fmt"
	"os"

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

	return nil
}
