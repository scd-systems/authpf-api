package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestNew tests config creation
func TestNew(t *testing.T) {
	cfg := New()

	assert.NotNil(t, cfg)
	assert.IsType(t, &ConfigFile{}, cfg)
}

// TestLoadConfig_ValidConfig tests loading a valid configuration file
func TestLoadConfig_ValidConfig(t *testing.T) {
	// Create a temporary config file
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	validConfig := `
defaults:
  pfctlBinary: /sbin/pfctl

server:
  bind: 127.0.0.1
  port: 8080
  logfile: /var/log/authpf-api.log
  elevatorMode: sudo
  jwtTokenTimeout: 8h
  jwtSecret: test-secret

authpf:
  timeout: 1h
  userRulesRootFolder: /etc/authpf
  userRulesFile: rules
  anchorName: authpf
  flushFilter:
    - nat
    - rules

rbac:
  roles:
    admin:
      permissions:
        - read
        - write
  users:
    testuser:
      password: test
      role: admin
`

	// Write config file with secure permissions (0640)
	err := os.WriteFile(configPath, []byte(validConfig), 0640)
	assert.NoError(t, err)

	// Load config
	cfg := New()
	err = cfg.LoadConfig(configPath)

	assert.NoError(t, err)
	assert.Equal(t, "/sbin/pfctl", cfg.Defaults.PfctlBinary)
	assert.Equal(t, "127.0.0.1", cfg.Server.Bind)
	assert.Equal(t, uint16(8080), cfg.Server.Port)
	assert.Equal(t, "1h", cfg.AuthPF.Timeout)
}

// TestLoadConfig_FileNotFound tests loading non-existent config file
func TestLoadConfig_FileNotFound(t *testing.T) {
	cfg := New()
	err := cfg.LoadConfig("/nonexistent/config.yaml")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot access config file")
}

// TestLoadConfig_InsecurePermissions tests loading config with insecure permissions
func TestLoadConfig_InsecurePermissions(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	validConfig := `
defaults:
  pfctlBinary: /sbin/pfctl

server:
  bind: 127.0.0.1
  port: 8080
  logfile: /var/log/authpf-api.log
  elevatorMode: sudo

authpf:
  timeout: 1h
  userRulesRootFolder: /etc/authpf
  userRulesFile: rules
  anchorName: authpf
  flushFilter:
    - nat
`

	// Write config file with insecure permissions (0644)
	err := os.WriteFile(configPath, []byte(validConfig), 0644)
	assert.NoError(t, err)

	cfg := New()
	err = cfg.LoadConfig(configPath)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "insecure permissions")
}

// TestLoadConfig_InvalidYAML tests loading invalid YAML config
func TestLoadConfig_InvalidYAML(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	invalidConfig := `
invalid: yaml: content: [
`

	err := os.WriteFile(configPath, []byte(invalidConfig), 0640)
	assert.NoError(t, err)

	cfg := New()
	err = cfg.LoadConfig(configPath)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot parse config file")
}

// TestValidateRequiredSections_MissingDefaults tests validation with missing defaults
func TestValidateRequiredSections_MissingDefaults(t *testing.T) {
	cfg := &ConfigFile{
		Server: ConfigFileServer{
			Bind:         "127.0.0.1",
			Port:         8080,
			Logfile:      "/var/log/authpf-api.log",
			ElevatorMode: "sudo",
		},
		AuthPF: ConfigFileAuthPF{
			Timeout:             "1h",
			UserRulesRootFolder: "/etc/authpf",
			UserRulesFile:       "rules",
			AnchorName:          "authpf",
			FlushFilter:         []string{"nat"},
		},
	}

	err := cfg.validateRequiredSections()

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "defaults.pfctlBinary")
}

// TestValidateRequiredSections_MissingServer tests validation with missing server fields
func TestValidateRequiredSections_MissingServer(t *testing.T) {
	cfg := &ConfigFile{
		Defaults: ConfigFileDefaults{
			PfctlBinary: "/sbin/pfctl",
		},
		AuthPF: ConfigFileAuthPF{
			Timeout:             "1h",
			UserRulesRootFolder: "/etc/authpf",
			UserRulesFile:       "rules",
			AnchorName:          "authpf",
			FlushFilter:         []string{"nat"},
		},
	}

	err := cfg.validateRequiredSections()

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "server.bind")
	assert.Contains(t, err.Error(), "server.port")
	assert.Contains(t, err.Error(), "server.logfile")
	assert.Contains(t, err.Error(), "server.elevatorMode")
}

// TestValidateRequiredSections_MissingAuthPF tests validation with missing authpf fields
func TestValidateRequiredSections_MissingAuthPF(t *testing.T) {
	cfg := &ConfigFile{
		Defaults: ConfigFileDefaults{
			PfctlBinary: "/sbin/pfctl",
		},
		Server: ConfigFileServer{
			Bind:         "127.0.0.1",
			Port:         8080,
			Logfile:      "/var/log/authpf-api.log",
			ElevatorMode: "sudo",
		},
	}

	err := cfg.validateRequiredSections()

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "authpf.timeout")
	assert.Contains(t, err.Error(), "authpf.userRulesRootFolder")
	assert.Contains(t, err.Error(), "authpf.userRulesFile")
	assert.Contains(t, err.Error(), "authpf.anchorName")
	assert.Contains(t, err.Error(), "authpf.flushFilter")
}

// TestValidateRequiredSections_ValidConfig tests validation with valid config
func TestValidateRequiredSections_ValidConfig(t *testing.T) {
	cfg := &ConfigFile{
		Defaults: ConfigFileDefaults{
			PfctlBinary: "/sbin/pfctl",
		},
		Server: ConfigFileServer{
			Bind:         "127.0.0.1",
			Port:         8080,
			Logfile:      "/var/log/authpf-api.log",
			ElevatorMode: "sudo",
		},
		AuthPF: ConfigFileAuthPF{
			Timeout:             "1h",
			UserRulesRootFolder: "/etc/authpf",
			UserRulesFile:       "rules",
			AnchorName:          "authpf",
			FlushFilter:         []string{"nat", "rules"},
		},
	}

	err := cfg.validateRequiredSections()

	assert.NoError(t, err)
}

// TestLoadConfig_CompleteValidConfig tests loading a complete valid configuration
func TestLoadConfig_CompleteValidConfig(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	completeConfig := `
defaults:
  pfctlBinary: /sbin/pfctl

server:
  bind: 0.0.0.0
  port: 9090
  logfile: /var/log/authpf-api.log
  elevatorMode: doas
  jwtTokenTimeout: 24h
  jwtSecret: my-secret-key

authpf:
  timeout: 2h
  userRulesRootFolder: /etc/authpf/rules
  userRulesFile: user.rules
  anchorName: authpf-anchor
  flushFilter:
    - nat
    - rules
    - states
  onShutdown: flush
  onStartup: load

rbac:
  roles:
    admin:
      permissions:
        - read
        - write
        - delete
    user:
      permissions:
        - read
  users:
    admin:
      password: admin-hash
      role: admin
      userId: 1
    user1:
      password: user-hash
      role: user
      userId: 1000
`

	err := os.WriteFile(configPath, []byte(completeConfig), 0640)
	assert.NoError(t, err)

	cfg := New()
	err = cfg.LoadConfig(configPath)

	assert.NoError(t, err)
	assert.Equal(t, "/sbin/pfctl", cfg.Defaults.PfctlBinary)
	assert.Equal(t, "0.0.0.0", cfg.Server.Bind)
	assert.Equal(t, uint16(9090), cfg.Server.Port)
	assert.Equal(t, "/var/log/authpf-api.log", cfg.Server.Logfile)
	assert.Equal(t, "doas", cfg.Server.ElevatorMode)
	assert.Equal(t, "24h", cfg.Server.JwtTokenTimeout)
	assert.Equal(t, "my-secret-key", cfg.Server.JwtSecret)
	assert.Equal(t, "2h", cfg.AuthPF.Timeout)
	assert.Equal(t, "/etc/authpf/rules", cfg.AuthPF.UserRulesRootFolder)
	assert.Equal(t, "user.rules", cfg.AuthPF.UserRulesFile)
	assert.Equal(t, "authpf-anchor", cfg.AuthPF.AnchorName)
	assert.Equal(t, 3, len(cfg.AuthPF.FlushFilter))
	assert.Equal(t, 2, len(cfg.Rbac.Roles))
	assert.Equal(t, 2, len(cfg.Rbac.Users))
}

// TestConfigFileTypes tests config file types structure
func TestConfigFileTypes(t *testing.T) {
	cfg := &ConfigFile{
		Defaults: ConfigFileDefaults{
			PfctlBinary: "/sbin/pfctl",
		},
		Server: ConfigFileServer{
			Bind:            "127.0.0.1",
			Port:            8080,
			Logfile:         "/var/log/authpf-api.log",
			ElevatorMode:    "sudo",
			JwtTokenTimeout: "8h",
			JwtSecret:       "secret",
			SSL: ConfigFileServerSSL{
				Certificate: "/etc/ssl/cert.pem",
				Key:         "/etc/ssl/key.pem",
			},
		},
		AuthPF: ConfigFileAuthPF{
			Timeout:             "1h",
			UserRulesRootFolder: "/etc/authpf",
			UserRulesFile:       "rules",
			AnchorName:          "authpf",
			FlushFilter:         []string{"nat"},
			OnShutdown:          "flush",
			OnStartup:           "load",
		},
		Rbac: ConfigFileRbac{
			Roles: map[string]ConfigFileRbacRoles{
				"admin": {
					Permissions: []string{"read", "write"},
				},
			},
			Users: map[string]ConfigFileRbacUsers{
				"admin": {
					Password:      "hash",
					Role:          "admin",
					UserID:        1,
					UserRulesFile: "admin.rules",
				},
			},
		},
	}

	assert.NotNil(t, cfg)
	assert.Equal(t, "/sbin/pfctl", cfg.Defaults.PfctlBinary)
	assert.Equal(t, "/etc/ssl/cert.pem", cfg.Server.SSL.Certificate)
	assert.Equal(t, 1, len(cfg.AuthPF.FlushFilter))
	assert.Equal(t, 1, len(cfg.Rbac.Roles))
	assert.Equal(t, 1, len(cfg.Rbac.Users))
}
