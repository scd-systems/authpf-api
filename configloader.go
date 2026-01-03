package main

import (
	"os"

	yaml "gopkg.in/yaml.v3"
)

func (config *ConfigFile) loadConfig(configFile string) error {
	yamlFile, err := os.ReadFile(configFile)
	if err == nil {
		err = yaml.Unmarshal(yamlFile, config)
	}
	return err
}
