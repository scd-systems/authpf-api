package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCollectUnknownKeys(t *testing.T) {
	tests := []struct {
		name      string
		yaml      string
		wantCount int
		wantMatch []string
	}{
		{
			name: "clean config reports nothing",
			yaml: `
defaults:
  pfctlBinary: /sbin/pfctl
authpf:
  timeout: 30m
  pfTable: authpf_users
rbac:
  roles:
    admin:
      permissions: [view_own_rules]
  users:
    alice:
      role: admin
      macros:
        server_1_port: "22"
`,
			wantCount: 0,
		},
		{
			name:      "misspelled pfTable is reported, not dropped silently",
			yaml:      "authpf:\n  pftable: authpf_users\n",
			wantCount: 1,
			wantMatch: []string{"pftable"},
		},
		{
			name:      "wrong case is a different key to the decoder",
			yaml:      "authpf:\n  PfTable: authpf_users\n",
			wantCount: 1,
			wantMatch: []string{"PfTable"},
		},
		{
			name:      "unknown top-level section",
			yaml:      "bogusTop:\n  x: 1\n",
			wantCount: 1,
			wantMatch: []string{"bogusTop"},
		},
		{
			name:      "typo nested under a user entry",
			yaml:      "rbac:\n  users:\n    alice:\n      pftable: t\n",
			wantCount: 1,
			wantMatch: []string{"pftable"},
		},
		{
			// The whole reason for deriving from struct tags instead of a
			// hand-written key list: arbitrary map keys are free.
			name:      "arbitrary role, user and macro names are not unknown",
			yaml:      "rbac:\n  roles:\n    weird.role-name:\n      permissions: [x]\n  users:\n    some.user-x:\n      macros:\n        anything_goes: v\n",
			wantCount: 0,
		},
		{
			name:      "several unknowns are all reported",
			yaml:      "zz: 1\nauthpf:\n  pftable: t\n",
			wantCount: 2,
		},
		{
			name:      "messages carry a line number",
			yaml:      "defaults:\n  pfctlBinary: /sbin/pfctl\n  nope: x\n",
			wantCount: 1,
			wantMatch: []string{"line 3", "nope"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := collectUnknownKeys([]byte(tt.yaml))
			assert.Len(t, got, tt.wantCount)
			for _, want := range tt.wantMatch {
				joined := ""
				for _, g := range got {
					joined += g + "\n"
				}
				assert.Contains(t, joined, want)
			}
		})
	}
}

// Every field of ConfigFile must be reachable by its yaml name. This decodes a
// document exercising every key in authpf-api.conf.sample and asserts nothing
// is reported unknown, which is what would break if a tag were renamed.
func TestCollectUnknownKeys_FullSampleShapeIsClean(t *testing.T) {
	full := `
defaults:
  pfctlBinary: /sbin/pfctl
authpf:
  timeout: 30m
  userRulesRootFolder: /etc/authpf/users
  userRulesFile: authpf.rules
  anchorName: authpf
  flushFilter: [nat, rules]
  onStartup: importflush
  onShutdown: flushall
  pfTable: authpf_users
server:
  bind: 127.0.0.1
  port: 8080
  ssl:
    certificate: /etc/ssl/c.pem
    key: /etc/ssl/k.pem
  jwtSecret: secret
  jwtTokenTimeout: 8
  elevatorMode: none
  logfile: /var/log/authpf-api.log
rbac:
  roles:
    admin:
      permissions: [view_own_rules]
  users:
    authpf-user1:
      userRulesFile: authpf.rules
      password: hash
      role: user
      userId: 1001
      userIp: 192.168.0.10
      pfTable: authpf_users
      macros:
        server_1_port: "22"
`
	assert.Empty(t, collectUnknownKeys([]byte(full)))
}
