package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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
  jwtSecret: my-secret-key-1234567890-1337-12

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

// base64SampleSecret is what "openssl rand -base64 32" produces, the value the
// docs recommend operators put into server.jwtSecret.
const base64SampleSecret = "n9YaRcsGDs/zkkzCR3NkbnWS7yOe/KnUYgASazPojGM="

// jwtSecretFixture returns a config that only differs in server.jwtSecret, so
// each case exercises the secret rule and nothing else.
func jwtSecretFixture(secret string) *ConfigFile {
	cfg := &ConfigFile{
		Defaults: ConfigFileDefaults{
			PfctlBinary: "/sbin/pfctl",
		},
		Server: ConfigFileServer{
			Bind:         "127.0.0.1",
			Port:         8080,
			Logfile:      "/var/log/authpf-api.log",
			ElevatorMode: "sudo",
			JwtSecret:    secret,
		},
		AuthPF: ConfigFileAuthPF{
			Timeout:             "1h",
			UserRulesRootFolder: "/etc/authpf",
			UserRulesFile:       "rules",
			AnchorName:          "authpf",
			FlushFilter:         []string{"nat"},
		},
	}
	return cfg
}

// TestValidateRequiredSections_JwtSecretStrength covers the RFC 7518 section
// 3.2 floor for server.jwtSecret. A configured HS256 key below 32 bytes can be
// recovered offline from a single issued token, which lets the attacker mint
// tokens for any configured user including admin.
func TestValidateRequiredSections_JwtSecretStrength(t *testing.T) {
	tests := []struct {
		name    string
		secret  string
		wantErr string
	}{
		{
			name:    "single character from the reported attack",
			secret:  "x",
			wantErr: "server.jwtSecret must be at least 32 characters, got 1",
		},
		{
			name:    "low entropy prose",
			secret:  "changeme",
			wantErr: "server.jwtSecret must be at least 32 characters, got 8",
		},
		{
			name:    "one byte below the floor",
			secret:  strings.Repeat("a", minJwtSecretLength-1),
			wantErr: fmt.Sprintf("must be at least %d characters, got %d", minJwtSecretLength, minJwtSecretLength-1),
		},
		{
			name:    "spaces only",
			secret:  "   ",
			wantErr: "server.jwtSecret is set but contains only whitespace",
		},
		{
			name:    "tab and newline only",
			secret:  "\t \n",
			wantErr: "server.jwtSecret is set but contains only whitespace",
		},
		{
			name:    "exactly at the floor",
			secret:  strings.Repeat("a", minJwtSecretLength),
			wantErr: "",
		},
		{
			name:    "base64 sample from openssl rand",
			secret:  base64SampleSecret,
			wantErr: "",
		},
		{
			name:    "unset keeps the random fallback",
			secret:  "",
			wantErr: "",
		},
		{
			name:    "long secret with inner whitespace",
			secret:  "correct horse battery staple hunter2",
			wantErr: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := jwtSecretFixture(tt.secret).validateRequiredSections()

			if tt.wantErr == "" {
				assert.NoError(t, err)
				return
			}

			require := assert.New(t)
			require.Error(err)
			require.Contains(err.Error(), tt.wantErr)
			// The error text goes to stderr and into the log, so the secret
			// itself must never appear in it.
			require.NotContains(err.Error(), tt.secret)
		})
	}
}

// TestLoadConfig_RejectsWeakJwtSecret proves the strength check is wired into
// LoadConfig, the only path that fills the signing key - a validator that is
// never reached would leave the offline-crack path open.
func TestLoadConfig_RejectsWeakJwtSecret(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		wantErr string
	}{
		{
			name:    "single character",
			yaml:    `jwtSecret: "x"`,
			wantErr: "server.jwtSecret must be at least 32 characters, got 1",
		},
		{
			name:    "quoted whitespace",
			yaml:    `jwtSecret: "    "`,
			wantErr: "server.jwtSecret is set but contains only whitespace",
		},
		{
			name:    "quoted short prose",
			yaml:    `jwtSecret: "your-secret-key"`,
			wantErr: "server.jwtSecret must be at least 32 characters, got 15",
		},
		{
			name:    "empty value falls back to a random secret",
			yaml:    `jwtSecret:`,
			wantErr: "",
		},
		{
			name:    "base64 sample from openssl rand",
			yaml:    `jwtSecret: "` + base64SampleSecret + `"`,
			wantErr: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			configPath := filepath.Join(t.TempDir(), "config.yaml")
			body := "defaults:\n  pfctlBinary: /sbin/pfctl\n\nserver:\n  bind: 127.0.0.1\n  port: 8080\n  logfile: /var/log/authpf-api.log\n  elevatorMode: sudo\n  " + tt.yaml + "\n\nauthpf:\n  timeout: 1h\n  userRulesRootFolder: /etc/authpf\n  userRulesFile: rules\n  anchorName: authpf\n  flushFilter:\n    - nat\n\nrbac:\n  roles:\n    admin:\n      permissions:\n        - read\n  users:\n    testuser:\n      password: test\n      role: admin\n"
			require := assert.New(t)
			require.NoError(os.WriteFile(configPath, []byte(body), 0640))

			err := New().LoadConfig(configPath)

			if tt.wantErr == "" {
				require.NoError(err)
				return
			}
			require.Error(err)
			require.Contains(err.Error(), tt.wantErr)
		})
	}
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
  jwtSecret: my-secret-key-1234567890-1337-12

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
	assert.Equal(t, "my-secret-key-1234567890-1337-12", cfg.Server.JwtSecret)
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

// maxValidTimeout is the documented upper bound for a token timeout: 30 days.
const maxValidTimeout = 30 * 24 * time.Hour

// TestValidateTokenTimeoutValueValid covers accepted timeout values.
func TestValidateTokenTimeoutValueValid(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  time.Duration
	}{
		{"hours only", "8", 8 * time.Hour},
		{"hours with unit", "8h", 8 * time.Hour},
		{"single minute", "1m", time.Minute},
		{"minutes", "30m", 30 * time.Minute},
		{"single hour", "1h", time.Hour},
		{"single day", "1d", 24 * time.Hour},
		{"two days", "2d", 48 * time.Hour},
		{"week in days", "7d", 168 * time.Hour},
		{"max as days", "30d", maxValidTimeout},
		{"max as hours", "720h", maxValidTimeout},
		{"leading zero", "08", 8 * time.Hour},
		{"surrounded by spaces", " 8h ", 8 * time.Hour},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ValidateTokenTimeoutValue(tt.input)
			assert.NoError(t, err, "input %q must be accepted", tt.input)
			assert.Equal(t, tt.want, got)
		})
	}
}

// TestValidateTokenTimeoutValueInvalid covers rejected timeout values.
// Only digits plus the unit letters d, h and m are allowed; anything above
// 30 days or not strictly positive is rejected.
func TestValidateTokenTimeoutValueInvalid(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"empty", ""},
		{"spaces only", "   "},
		{"no digits", "hours"},
		{"unit only", "d"},
		{"unknown unit", "8x"},
		{"week unit", "1w"},
		{"uppercase day", "1D"},
		{"seconds unit", "30s"},
		{"combined units", "1d12h"},
		{"double unit", "30mm"},
		{"unit before digits", "m30"},
		{"inner space", "30 h"},
		{"fraction", "1.5h"},
		{"minus sign", "-1h"},
		{"plus sign", "+8"},
		{"zero hours", "0"},
		{"zero minutes", "0m"},
		{"one hour over max", "721h"},
		{"one day over max", "31d"},
		{"far over max", "1000h"},
		{"digit overflow", "99999999999999999999h"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ValidateTokenTimeoutValue(tt.input)
			assert.Error(t, err, "input %q must be rejected", tt.input)
			assert.Equal(t, time.Duration(0), got, "must return zero duration on error")
		})
	}
}

// TestValidateTokenTimeoutValueErrorMessages locks in the hints users see in
// the server log when their config is wrong.
func TestValidateTokenTimeoutValueErrorMessages(t *testing.T) {
	_, err := ValidateTokenTimeoutValue("8x")
	assert.ErrorContains(t, err, "invalid token timeout")

	_, err = ValidateTokenTimeoutValue("31d")
	assert.ErrorContains(t, err, "maximum")
}
