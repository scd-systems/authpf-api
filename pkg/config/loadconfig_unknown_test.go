package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

// A config with a misspelled pfTable must surface the typo via UnknownKeys.
func TestLoadConfig_ReportsMisspelledKey(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "c.yaml")
	body := `
defaults:
  pfctlBinary: /sbin/pfctl
server:
  bind: 127.0.0.1
  port: 8080
  logfile: /tmp/l
  elevatorMode: none
authpf:
  timeout: 30m
  userRulesRootFolder: /etc/authpf/users
  userRulesFile: authpf.rules
  anchorName: authpf
  flushFilter: [rules]
  pftable: authpf_users
`
	assert.NoError(t, os.WriteFile(f, []byte(body), 0640))
	c := New()
	assert.NoError(t, c.LoadConfig(f))
	assert.Len(t, c.UnknownKeys, 1)
	assert.Contains(t, c.UnknownKeys[0], "pftable")
	assert.Contains(t, c.UnknownKeys[0], "ConfigFileAuthPF")
	assert.Contains(t, c.UnknownKeys[0], "line ")
}
