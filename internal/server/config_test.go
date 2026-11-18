package server

import (
	"bytes"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scd-systems/authpf-api/pkg/config"
)

// fixturePasswordHash is bcrypt("fixture-password"), generated once with
// -gen-user-password so shared fixtures pass the startup RBAC checks without
// paying the bcrypt cost per subtest.
const fixturePasswordHash = "$2a$10$oGxmBdYaMNJa6NO/FyZrN.Ku1GSbJOPaGiGUSlqeUrLJXyxspMNjS"

func TestCollectRequiredPfTables_Empty(t *testing.T) {
	cfg := &config.ConfigFile{
		AuthPF: config.ConfigFileAuthPF{PfTable: ""},
		Rbac: config.ConfigFileRbac{
			Users: map[string]config.ConfigFileRbacUsers{
				"user1": {PfTable: ""},
				"user2": {PfTable: ""},
			},
		},
	}
	result := gatherPfTablesFromConfig(cfg)
	assert.Empty(t, result, "should return empty slice when no pfTable configured anywhere")
}

func TestCollectRequiredPfTables_GlobalOnly(t *testing.T) {
	cfg := &config.ConfigFile{
		AuthPF: config.ConfigFileAuthPF{PfTable: "global_table"},
		Rbac: config.ConfigFileRbac{
			Users: map[string]config.ConfigFileRbacUsers{
				"user1": {PfTable: ""},
			},
		},
	}
	result := gatherPfTablesFromConfig(cfg)
	assert.Equal(t, []string{"global_table"}, result)
}

func TestCollectRequiredPfTables_UserOnly(t *testing.T) {
	cfg := &config.ConfigFile{
		AuthPF: config.ConfigFileAuthPF{PfTable: ""},
		Rbac: config.ConfigFileRbac{
			Users: map[string]config.ConfigFileRbacUsers{
				"user1": {PfTable: "user1_table"},
			},
		},
	}
	result := gatherPfTablesFromConfig(cfg)
	assert.Len(t, result, 1)
	assert.Contains(t, result, "user1_table")
}

func TestCollectRequiredPfTables_GlobalAndUser(t *testing.T) {
	cfg := &config.ConfigFile{
		AuthPF: config.ConfigFileAuthPF{PfTable: "global_table"},
		Rbac: config.ConfigFileRbac{
			Users: map[string]config.ConfigFileRbacUsers{
				"user1": {PfTable: "user1_table"},
			},
		},
	}
	result := gatherPfTablesFromConfig(cfg)
	assert.Len(t, result, 2)
	assert.Contains(t, result, "global_table")
	assert.Contains(t, result, "user1_table")
}

func TestCollectRequiredPfTables_DeduplicatesSameTableName(t *testing.T) {
	cfg := &config.ConfigFile{
		AuthPF: config.ConfigFileAuthPF{PfTable: "shared_table"},
		Rbac: config.ConfigFileRbac{
			Users: map[string]config.ConfigFileRbacUsers{
				"user1": {PfTable: "shared_table"},
				"user2": {PfTable: "shared_table"},
			},
		},
	}
	result := gatherPfTablesFromConfig(cfg)
	assert.Len(t, result, 1, "duplicate table names must be deduplicated")
	assert.Contains(t, result, "shared_table")
}

func TestCollectRequiredPfTables_MultipleUsersDistinctTables(t *testing.T) {
	cfg := &config.ConfigFile{
		AuthPF: config.ConfigFileAuthPF{PfTable: "global_table"},
		Rbac: config.ConfigFileRbac{
			Users: map[string]config.ConfigFileRbacUsers{
				"user1": {PfTable: "table_a"},
				"user2": {PfTable: "table_b"},
				"user3": {PfTable: ""},
				"user4": {PfTable: "global_table"},
			},
		},
	}
	result := gatherPfTablesFromConfig(cfg)
	assert.Len(t, result, 3)
	assert.Contains(t, result, "global_table")
	assert.Contains(t, result, "table_a")
	assert.Contains(t, result, "table_b")
}

func TestCollectRequiredPfTables_NoUsers(t *testing.T) {
	cfg := &config.ConfigFile{
		AuthPF: config.ConfigFileAuthPF{PfTable: "global_table"},
		Rbac: config.ConfigFileRbac{
			Users: map[string]config.ConfigFileRbacUsers{},
		},
	}
	result := gatherPfTablesFromConfig(cfg)
	assert.Equal(t, []string{"global_table"}, result)
}

// validRBAC is a complete, valid RBAC section. validateConfig() runs the whole
// file validation before it can warn, so this test needs a config that passes
// every check. The identical fixture lives in pkg/config/config_test.go, where
// the RBAC checks themselves are tested - test helpers cannot be shared across
// packages, and duplicating six lines is cheaper than exporting test helpers
// from the library.
func validRBAC() config.ConfigFileRbac {
	return config.ConfigFileRbac{
		Roles: map[string]config.ConfigFileRbacRoles{
			"admin": {Permissions: []string{config.RBAC_ACTIVATE_OWN_RULE}},
		},
		Users: map[string]config.ConfigFileRbacUsers{
			"admin": {Password: fixturePasswordHash, Role: "admin", UserID: 1000},
		},
	}
}

// TestValidateConfig_SchedulerIntervalWarnsOnLongInterval covers the soft limit:
// anything above 30 minutes stays accepted, but the operator has to see that
// anchors are only revoked on the next loop and therefore live up to a full
// interval past their own timeout.
func TestValidateConfig_SchedulerIntervalWarnsOnLongInterval(t *testing.T) {
	tests := []struct {
		name     string
		interval string
		warns    bool
	}{
		{name: "default does not warn", interval: "", warns: false},
		{name: "60 seconds does not warn", interval: "60", warns: false},
		{name: "exactly the threshold does not warn", interval: "30m", warns: false},
		{name: "one second over the threshold warns", interval: "30m1s", warns: true},
		{name: "one hour warns", interval: "1h", warns: true},
		{name: "the maximum warns", interval: "720h", warns: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logs := &bytes.Buffer{}
			s := &Server{
				logger: zerolog.New(logs),
				config: &config.ConfigFile{
					Rbac:   validRBAC(),
					AuthPF: config.ConfigFileAuthPF{SchedulerInterval: tt.interval},
				},
			}

			err := s.validateConfig()
			require.NoError(t, err, "schedulerInterval %q must be accepted", tt.interval)

			if tt.warns {
				assert.Contains(t, logs.String(), "authpf.schedulerInterval")
				assert.Contains(t, logs.String(), "\"level\":\"warn\"")
			} else {
				assert.NotContains(t, logs.String(), "authpf.schedulerInterval")
			}
		})
	}
}
