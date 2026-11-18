package server

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scd-systems/authpf-api/pkg/config"
)

func TestValidateMacroKey(t *testing.T) {
	tests := []struct {
		name    string
		key     string
		wantErr bool
		errMsg  string
	}{
		{name: "plain key", key: "my_macro", wantErr: false},
		{name: "uppercase key", key: "SERVER_1_PORT", wantErr: false},
		// errMsg carries the full charset here so the message and the regex
		// cannot drift apart silently again.
		{
			name:    "leading underscore rejected, pf.conf documents letter-first",
			key:     "_internal",
			wantErr: true,
			errMsg:  `invalid macro key "_internal", only [A-Za-z][A-Za-z0-9_]* allowed`,
		},
		{name: "reserved-looking but distinct key", key: "user_ip2", wantErr: false},
		{name: "mixed case is not the reserved name", key: "User_Ip", wantErr: false},
		{
			name:    "user_ip always rejected, the app passes -D user_ip itself",
			key:     "user_ip",
			wantErr: true,
			errMsg:  "collides with the built-in pfctl macro",
		},
		{
			name:    "user_id always rejected, the app passes -D user_id itself",
			key:     "user_id",
			wantErr: true,
			errMsg:  "collides with the built-in pfctl macro",
		},
		{name: "empty key", key: "", wantErr: true, errMsg: "invalid macro key"},
		{name: "leading digit", key: "1port", wantErr: true, errMsg: "invalid macro key"},
		{name: "hyphen", key: "my-macro", wantErr: true, errMsg: "invalid macro key"},
		{name: "dot", key: "my.macro", wantErr: true, errMsg: "invalid macro key"},
		{name: "space", key: "my macro", wantErr: true, errMsg: "invalid macro key"},
		{name: "shell metacharacters", key: "x;rm", wantErr: true, errMsg: "invalid macro key"},
		{name: "argv injection shape", key: "x=1 -F all", wantErr: true, errMsg: "invalid macro key"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateMacroKey(tt.key)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateLength(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		minLen  int
		maxLen  int
		wantErr bool
		errMsg  string
	}{
		{
			name:    "valid value within bounds",
			value:   "hello",
			minLen:  1,
			maxLen:  128,
			wantErr: false,
		},
		{
			name:    "value at minimum length",
			value:   "a",
			minLen:  1,
			maxLen:  128,
			wantErr: false,
		},
		{
			name:    "value at maximum length",
			value:   "abcdefghij",
			minLen:  1,
			maxLen:  10,
			wantErr: false,
		},
		{
			name:    "value below minimum length",
			value:   "",
			minLen:  1,
			maxLen:  128,
			wantErr: true,
			errMsg:  "below minimum length",
		},
		{
			name:    "value exceeds maximum length",
			value:   "toolongvalue",
			minLen:  1,
			maxLen:  5,
			wantErr: true,
			errMsg:  "exceeds maximum length",
		},
		{
			name:    "multibyte UTF-8 runes counted correctly",
			value:   "日本語テスト",
			minLen:  1,
			maxLen:  5,
			wantErr: true,
			errMsg:  "exceeds maximum length",
		},
		{
			name:    "multibyte UTF-8 runes within max",
			value:   "日本語",
			minLen:  1,
			maxLen:  5,
			wantErr: false,
		},
		{
			name:    "exact minimum equals maximum",
			value:   "x",
			minLen:  1,
			maxLen:  1,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateLength(tt.value, tt.minLen, tt.maxLen)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateAlphanumericASCII(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		wantErr bool
		errMsg  string
	}{
		{
			name:    "valid lowercase letters",
			value:   "hello",
			wantErr: false,
		},
		{
			name:    "valid uppercase letters",
			value:   "HELLO",
			wantErr: false,
		},
		{
			name:    "valid digits",
			value:   "12345",
			wantErr: false,
		},
		{
			name:    "valid mixed alphanumeric",
			value:   "Hello123",
			wantErr: false,
		},
		{
			name:    "valid with underscore",
			value:   "hello_world",
			wantErr: false,
		},
		{
			name:    "valid with dot",
			value:   "hello.world",
			wantErr: false,
		},
		{
			name:    "valid all allowed special chars",
			value:   "A1_b2.C3",
			wantErr: false,
		},
		{
			name:    "empty string",
			value:   "",
			wantErr: true,
			errMsg:  "input must not be empty",
		},
		{
			name:    "contains space",
			value:   "hello world",
			wantErr: true,
			errMsg:  "invalid characters found in config parameter",
		},
		{
			name:    "contains hyphen",
			value:   "hello-world",
			wantErr: true,
			errMsg:  "invalid characters found in config parameter",
		},
		{
			name:    "contains slash",
			value:   "hello/world",
			wantErr: true,
			errMsg:  "invalid characters found in config parameter",
		},
		{
			name:    "contains at-sign",
			value:   "user@host",
			wantErr: true,
			errMsg:  "invalid characters found in config parameter",
		},
		{
			name:    "contains unicode character",
			value:   "héllo",
			wantErr: true,
			errMsg:  "invalid characters found in config parameter",
		},
		{
			name:    "contains semicolon",
			value:   "val;ue",
			wantErr: true,
			errMsg:  "invalid characters found in config parameter",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateAlphanumericASCII(tt.name, tt.value)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateIPAddr(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		wantErr bool
		errMsg  string
	}{
		{
			name:    "empty string is allowed (optional field)",
			value:   "",
			wantErr: false,
		},
		{
			name:    "valid IPv4 address",
			value:   "192.168.1.1",
			wantErr: false,
		},
		{
			name:    "valid IPv4 loopback",
			value:   "127.0.0.1",
			wantErr: false,
		},
		{
			name:    "valid IPv4 broadcast",
			value:   "255.255.255.255",
			wantErr: false,
		},
		{
			name:    "valid IPv6 address",
			value:   "2001:db8::1",
			wantErr: false,
		},
		{
			name:    "valid IPv6 loopback",
			value:   "::1",
			wantErr: false,
		},
		{
			name:    "valid IPv6 full address",
			value:   "fe80::1ff:fe23:4567:890a",
			wantErr: false,
		},
		{
			name:    "invalid IP - random string",
			value:   "not-an-ip",
			wantErr: true,
			errMsg:  "invalid userIP address found in config file",
		},
		{
			name:    "invalid IP - out of range octet",
			value:   "999.999.999.999",
			wantErr: true,
			errMsg:  "invalid userIP address found in config file",
		},
		{
			name:    "invalid IP - incomplete address",
			value:   "192.168.1",
			wantErr: true,
			errMsg:  "invalid userIP address found in config file",
		},
		{
			name:    "invalid IP - CIDR notation not accepted",
			value:   "192.168.1.0/24",
			wantErr: true,
			errMsg:  "invalid userIP address found in config file",
		},
		{
			name:    "whitespace-only string",
			value:   "   ",
			wantErr: true,
			errMsg:  "empty userIP address found in config file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateIPAddr(tt.value)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

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

// TestValidateConfig_JwtTokenTimeout checks that a broken jwtTokenTimeout is
// reported at startup instead of failing the first login with HTTP 500.
func TestValidateConfig_JwtTokenTimeout(t *testing.T) {
	tests := []struct {
		name    string
		timeout string
		wantErr bool
	}{
		{name: "unset falls back to the login default", timeout: "", wantErr: false},
		{name: "bare number is hours", timeout: "8", wantErr: false},
		{name: "days accepted", timeout: "2d", wantErr: false},
		{name: "maximum accepted", timeout: "30d", wantErr: false},
		{name: "unknown unit rejected", timeout: "8x", wantErr: true},
		{name: "above maximum rejected", timeout: "31d", wantErr: true},
		{name: "zero rejected", timeout: "0", wantErr: true},
		{name: "negative rejected", timeout: "-1h", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Server{
				logger: zerolog.Nop(),
				config: &config.ConfigFile{
					Rbac:   validRBAC(),
					Server: config.ConfigFileServer{JwtTokenTimeout: tt.timeout},
				},
			}
			err := s.validateConfig()
			if tt.wantErr {
				assert.Error(t, err, "jwtTokenTimeout %q must be rejected", tt.timeout)
				assert.ErrorContains(t, err, "server.jwtTokenTimeout")
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// Goes through validateConfig rather than the validator directly, so the same
// test compiles before and after the fix and demonstrates the behavior change.
func TestValidateConfig_RejectsHostileMacroKeys(t *testing.T) {
	tests := []struct {
		name    string
		key     string
		wantErr bool
	}{
		{name: "plain key accepted", key: "server_1_port", wantErr: false},
		{name: "argv injection shape rejected", key: "x=1 -F all", wantErr: true},
		{name: "hyphen rejected", key: "my-macro", wantErr: true},
		{name: "shell metacharacter rejected", key: "x;rm", wantErr: true},
		{name: "user_ip rejected even when userIp is unset", key: "user_ip", wantErr: true},
		{name: "user_id rejected even when userId is unset", key: "user_id", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Server{
				logger: zerolog.Nop(),
				config: &config.ConfigFile{
					Rbac: config.ConfigFileRbac{
						Roles: map[string]config.ConfigFileRbacRoles{
							"user": {Permissions: []string{config.RBAC_ACTIVATE_OWN_RULE}},
						},
						Users: map[string]config.ConfigFileRbacUsers{
							"alice": {
								Password: fixturePasswordHash,
								Role:     "user",
								Macros:   map[string]string{tt.key: "value"},
							},
						},
					},
				},
			}
			err := s.validateConfig()
			if tt.wantErr {
				assert.Error(t, err, "macro key %q must be rejected", tt.key)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestValidateConfig_SchedulerInterval covers the scheduler loop interval.
// Before the check existed, a negative, zero or sub-second value reached
// time.NewTicker in the scheduler goroutine and panicked the process after a
// successful startup, so an operator only saw the crash in the log.
// Goes through validateConfig rather than the validator directly, so the test
// covers the gate the server actually runs.
func TestValidateConfig_SchedulerInterval(t *testing.T) {
	tests := []struct {
		name     string
		interval string
		wantErr  bool
		errMsg   string
	}{
		{name: "unset falls back to the 60s default", interval: "", wantErr: false},
		{name: "bare number is seconds, the documented form", interval: "60", wantErr: false},
		{name: "smallest allowed value", interval: "1", wantErr: false},
		{name: "seconds unit", interval: "2s", wantErr: false},
		{name: "minutes unit", interval: "15m", wantErr: false},
		{name: "hours unit", interval: "1h", wantErr: false},
		{name: "surrounded by spaces", interval: " 30s ", wantErr: false},
		{name: "negative duration rejected", interval: "-5s", wantErr: true, errMsg: "authpf.schedulerInterval"},
		{name: "negative bare number rejected", interval: "-1", wantErr: true, errMsg: "authpf.schedulerInterval"},
		{name: "zero rejected", interval: "0", wantErr: true, errMsg: "below the minimum of 1s"},
		{name: "zero with unit rejected", interval: "0s", wantErr: true, errMsg: "below the minimum of 1s"},
		{name: "sub-second would truncate to a non-positive ticker", interval: "500ms", wantErr: true, errMsg: "below the minimum of 1s"},
		{name: "unknown unit rejected", interval: "60x", wantErr: true, errMsg: "authpf.schedulerInterval"},
		{name: "unit without digits rejected", interval: "s", wantErr: true, errMsg: "authpf.schedulerInterval"},
		{name: "text rejected", interval: "abc", wantErr: true, errMsg: "authpf.schedulerInterval"},
		{name: "exponent notation rejected", interval: "1e3", wantErr: true, errMsg: "authpf.schedulerInterval"},
		{name: "unit overflow rejected", interval: "99999999999999999999h", wantErr: true, errMsg: "authpf.schedulerInterval"},
		{name: "maximum of 30 days accepted", interval: "720h", wantErr: false},
		{name: "maximum as bare seconds accepted", interval: "2592000", wantErr: false},
		{name: "above maximum rejected", interval: "721h", wantErr: true, errMsg: "exceeds the maximum of 30 days"},
		{name: "one second above maximum rejected", interval: "2592001s", wantErr: true, errMsg: "exceeds the maximum of 30 days"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Server{
				logger: zerolog.Nop(),
				config: &config.ConfigFile{
					Rbac:   validRBAC(),
					AuthPF: config.ConfigFileAuthPF{SchedulerInterval: tt.interval},
				},
			}
			err := s.validateConfig()
			if tt.wantErr {
				assert.Error(t, err, "schedulerInterval %q must be rejected", tt.interval)
				assert.ErrorContains(t, err, tt.errMsg)
			} else {
				assert.NoError(t, err)
			}
		})
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

// extensionsTestServer builds a server whose validateExtensions() can be called
// directly. Rbac is filled with the shared fixture so the same config can also
// go through validateConfig().
func extensionsTestServer(exts ...config.ConfigFileExtension) *Server {
	return &Server{
		config: &config.ConfigFile{
			Server:     config.ConfigFileServer{JwtTokenTimeout: "8h"},
			Rbac:       validRBAC(),
			Extensions: exts,
		},
		logger: zerolog.New(&bytes.Buffer{}),
	}
}

func extensionsName(name string, cfg map[string]any) config.ConfigFileExtension {
	return config.ConfigFileExtension{Name: name, Config: cfg}
}

func TestValidateExtensions_List(t *testing.T) {
	tests := []struct {
		name    string
		exts    []config.ConfigFileExtension
		wantErr bool
		errMsg  string
	}{
		{name: "no extensions section", exts: nil, wantErr: false},
		{name: "empty list", exts: []config.ConfigFileExtension{}, wantErr: false},
		{name: "single registered-looking name", exts: []config.ConfigFileExtension{{Name: "ratelimit"}}, wantErr: false},
		{
			name: "three distinct names",
			exts: []config.ConfigFileExtension{
				{Name: "prometheus-metrics"},
				{Name: "ratelimit"},
				{Name: "file-rbac"},
			},
			wantErr: false,
		},
		{
			name:    "entry without name",
			exts:    []config.ConfigFileExtension{{Name: "ratelimit"}, {Name: ""}},
			wantErr: true,
			errMsg:  "extension entry without name",
		},
		{
			name:    "name with space",
			exts:    []config.ConfigFileExtension{{Name: "rate limit"}},
			wantErr: true,
			errMsg:  `invalid extensions[].name: "rate limit"`,
		},
		{
			name:    "name with slash",
			exts:    []config.ConfigFileExtension{{Name: "ext/ratelimit"}},
			wantErr: true,
			errMsg:  `invalid extensions[].name: "ext/ratelimit"`,
		},
		{
			name:    "path traversal name",
			exts:    []config.ConfigFileExtension{{Name: "../etc/passwd"}},
			wantErr: true,
			errMsg:  `invalid extensions[].name: "../etc/passwd"`,
		},
		{
			name:    "leading digit is allowed",
			exts:    []config.ConfigFileExtension{{Name: "1ext"}},
			wantErr: false,
		},
		{
			name:    "leading underscore rejected",
			exts:    []config.ConfigFileExtension{{Name: "_ext"}},
			wantErr: true,
			// The full pattern is asserted once so message and regex cannot
			// drift apart silently.
			errMsg: "only ^[A-Za-z0-9][A-Za-z0-9._-]*$ allowed",
		},
		{
			name:    "whitespace only name rejected",
			exts:    []config.ConfigFileExtension{{Name: "   "}},
			wantErr: true,
			errMsg:  "invalid extensions[].name",
		},
		{
			name:    "name with newline rejected, keeps log lines single-line",
			exts:    []config.ConfigFileExtension{{Name: "ext\ninjected"}},
			wantErr: true,
			errMsg:  "invalid extensions[].name",
		},
		{
			// The specified pattern is charset-only, so a long but well-formed
			// name stays valid; length is not capped here.
			name: "255 character name is allowed",
			exts: []config.ConfigFileExtension{{Name: strings.Repeat("a", 255)}},
		},
		{
			name:    "255 character name with a space is rejected",
			exts:    []config.ConfigFileExtension{{Name: strings.Repeat("a", 254) + " "}},
			wantErr: true,
			errMsg:  "invalid extensions[].name",
		},
		{
			name: "duplicate name names the extension and the count",
			exts: []config.ConfigFileExtension{
				{Name: "ratelimit"},
				{Name: "prometheus-metrics"},
				{Name: "ratelimit"},
			},
			wantErr: true,
			errMsg:  `"ratelimit" configured 2 times`,
		},
		{
			name: "threefold duplicate reports three",
			exts: []config.ConfigFileExtension{
				{Name: "file-rbac"},
				{Name: "file-rbac"},
				{Name: "file-rbac"},
			},
			wantErr: true,
			errMsg:  `"file-rbac" configured 3 times`,
		},
		{
			name: "names differing only in config are still duplicates",
			exts: []config.ConfigFileExtension{
				{Name: "ratelimit", Config: map[string]any{"rate": 10}},
				{Name: "ratelimit", Config: map[string]any{"rate": 20}},
			},
			wantErr: true,
			errMsg:  "duplicate extensions[].name",
		},
		{
			name: "empty name wins over invalid name, unnamed is the louder bug",
			exts: []config.ConfigFileExtension{
				{Name: "bad name"},
				{Name: ""},
			},
			wantErr: true,
			errMsg:  "extension entry without name",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := extensionsTestServer(tt.exts...).validateExtensions()
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// The messages must not change when an operator reorders the extensions list,
// so both orderings have to produce the identical error string.
func TestValidateExtensions_MessagesAreConfigOrderIndependent(t *testing.T) {
	tests := []struct {
		name string
		exts [2][]config.ConfigFileExtension
	}{
		{
			name: "duplicates",
			exts: [2][]config.ConfigFileExtension{
				{{Name: "ratelimit"}, {Name: "file-rbac"}, {Name: "ratelimit"}, {Name: "file-rbac"}},
				{{Name: "file-rbac"}, {Name: "ratelimit"}, {Name: "file-rbac"}, {Name: "ratelimit"}},
			},
		},
		{
			name: "invalid names",
			exts: [2][]config.ConfigFileExtension{
				{{Name: "z bad"}, {Name: "a/b"}},
				{{Name: "a/b"}, {Name: "z bad"}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errA := extensionsTestServer(tt.exts[0]...).validateExtensions()
			errB := extensionsTestServer(tt.exts[1]...).validateExtensions()
			require.Error(t, errA)
			require.Error(t, errB)
			assert.Equal(t, errA.Error(), errB.Error(), "error must not depend on the config order")
		})
	}
}

// extensions[].config is a map[string]any owned by the extensions themselves,
// which live in a separate repository. Anything in it must pass here.
func TestValidateExtensions_ConfigIsNotInspected(t *testing.T) {
	tests := []struct {
		name string
		cfg  map[string]any
	}{
		{name: "nil config", cfg: nil},
		{name: "empty config", cfg: map[string]any{}},
		{name: "unknown keys", cfg: map[string]any{"ratea": 10, "typo": true}},
		{
			name: "nested and typed values",
			cfg: map[string]any{
				"listen":  map[string]any{"/metrics": nil},
				"rate":    "not-a-number",
				"list":    []any{1, "two", 3.5},
				"missing": struct{ A int }{A: 1},
			},
		},
		{
			name: "hostile looking values and keys",
			cfg:  map[string]any{";rm -rf /": "$(reboot)", "path": "../../etc/shadow", "": ""},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := extensionsTestServer(extensionsName("ratelimit", tt.cfg)).validateExtensions()
			assert.NoError(t, err, "config content must be left to the extension itself")
		})
	}
}

// An unknown extension is out of scope here: validateExtensions runs before
// loadExtensions, which is where "extension %q not found" is reported.
func TestValidateExtensions_UnknownNameIsNotRejectedHere(t *testing.T) {
	err := extensionsTestServer([]config.ConfigFileExtension{{Name: "no-such-extension"}}...).validateExtensions()
	assert.NoError(t, err)
}

// Goes through validateConfig with a full, otherwise valid configuration, so
// the gate the server actually runs is covered. Path, TLS, pfctl and lifecycle
// fields are left empty on purpose: they belong to the other work packages and
// their empty values are valid.
func TestValidateConfig_Extensions(t *testing.T) {
	tests := []struct {
		name    string
		exts    []config.ConfigFileExtension
		wantErr bool
		errMsg  string
	}{
		{name: "no extensions", exts: nil, wantErr: false},
		{
			name: "distinct names with config",
			exts: []config.ConfigFileExtension{
				{Name: "prometheus-metrics"},
				{Name: "ratelimit", Config: map[string]any{"rate": 10}},
			},
			wantErr: false,
		},
		{
			name:    "duplicate blocks startup",
			exts:    []config.ConfigFileExtension{{Name: "ratelimit"}, {Name: "ratelimit"}},
			wantErr: true,
			errMsg:  "duplicate extensions[].name",
		},
		{
			name:    "nameless entry blocks startup",
			exts:    []config.ConfigFileExtension{{Name: "ratelimit"}, {}},
			wantErr: true,
			errMsg:  "extension entry without name",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := extensionsTestServer(tt.exts...)
			s.config.Defaults = config.ConfigFileDefaults{}
			s.config.AuthPF = config.ConfigFileAuthPF{
				AnchorName:        "authpf",
				PfTable:           "authpf_anchors",
				SchedulerInterval: "60",
			}
			s.config.Server.Bind = "127.0.0.1"
			s.config.Server.Port = 8080

			err := s.validateConfig()
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// fixturePasswordHash is bcrypt("fixture-password"), generated once with
// -gen-user-password so shared fixtures pass the startup RBAC checks without
// paying the bcrypt cost per subtest.
const fixturePasswordHash = "$2a$10$oGxmBdYaMNJa6NO/FyZrN.Ku1GSbJOPaGiGUSlqeUrLJXyxspMNjS"

// validRBAC returns the smallest rbac section that satisfies every startup
// check, so a test isolating one unrelated parameter is not tripped by it.
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

// pathsTestServer builds a Server that only carries a config, the shape every
// validator in the server package is tested against.
func pathsTestServer(cfg *config.ConfigFile) *Server {
	return &Server{config: cfg, logger: zerolog.New(&bytes.Buffer{})}
}

// pathsWriteKeyPair writes a self-signed certificate with its private key into
// dir and returns both paths. Generated in-process so the test needs neither
// openssl nor any file below /etc.
func pathsWriteKeyPair(t *testing.T, dir, commonName string) (string, string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)

	certPath := filepath.Join(dir, commonName+".crt")
	certFile, err := os.Create(certPath)
	require.NoError(t, err)
	require.NoError(t, pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: der}))
	require.NoError(t, certFile.Close())

	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	keyPath := filepath.Join(dir, commonName+".key")
	keyFile, err := os.OpenFile(keyPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	require.NoError(t, err)
	require.NoError(t, pem.Encode(keyFile, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	require.NoError(t, keyFile.Close())

	return certPath, keyPath
}

// Finding 7: authpf.anchorName lands in `pfctl -a <anchorName>/<user>(<id>)`.
func TestPathsValidateAnchorName(t *testing.T) {
	tests := []struct {
		name       string
		anchorName string
		wantErr    bool
		errMsg     string
	}{
		{name: "shipped default", anchorName: "authpf"},
		{name: "with underscore", anchorName: "authpf_api"},
		{name: "with dot", anchorName: "net.example"},
		{name: "with digits", anchorName: "authpf2"},
		{name: "empty is required elsewhere", anchorName: ""},
		{
			name:       "path separator rejected, it would open another anchor",
			anchorName: "authpf/../../pf",
			wantErr:    true,
			errMsg:     "invalid characters found in config parameter: authpf.anchorName",
		},
		{
			name:       "space rejected, it would split the pfctl argument",
			anchorName: "auth pf",
			wantErr:    true,
			errMsg:     "authpf.anchorName",
		},
		{
			name:       "shell metacharacter rejected",
			anchorName: "authpf;rm -f /",
			wantErr:    true,
			errMsg:     "authpf.anchorName",
		},
		{name: "dash rejected", anchorName: "-authpf", wantErr: true, errMsg: "authpf.anchorName"},
		{name: "angle bracket rejected", anchorName: "authpf(1)", wantErr: true, errMsg: "authpf.anchorName"},
		{name: "non ASCII rejected", anchorName: "authpäf", wantErr: true, errMsg: "authpf.anchorName"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := pathsTestServer(&config.ConfigFile{
				AuthPF: config.ConfigFileAuthPF{AnchorName: tt.anchorName},
			})
			err := s.validatePathsAndTLS()
			if tt.wantErr {
				require.Error(t, err, "anchorName %q must be rejected", tt.anchorName)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// Finding 8: authpf.userRulesRootFolder is the base of every activation.
func TestPathsValidateUserRulesRoot(t *testing.T) {
	tmp := t.TempDir()

	rulesDir := filepath.Join(tmp, "users")
	require.NoError(t, os.Mkdir(rulesDir, 0750))

	notADir := filepath.Join(tmp, "authpf.rules")
	require.NoError(t, os.WriteFile(notADir, []byte("pass all\n"), 0640))

	emptyFileDir := filepath.Join(tmp, "empty")
	require.NoError(t, os.Mkdir(emptyFileDir, 0750))

	unreadable := filepath.Join(tmp, "unreadable")
	require.NoError(t, os.Mkdir(unreadable, 0700))
	require.NoError(t, os.Chmod(unreadable, 0000))
	t.Cleanup(func() { _ = os.Chmod(unreadable, 0700) })

	tests := []struct {
		name    string
		path    string
		wantErr bool
		errMsg  string
		skip    bool
	}{
		{name: "existing readable directory", path: rulesDir},
		{name: "empty directory is fine", path: emptyFileDir},
		{name: "empty value is required elsewhere", path: ""},
		{
			name:    "relative path rejected",
			path:    "users",
			wantErr: true,
			errMsg:  "authpf.userRulesRootFolder must be an absolute path, got: users",
		},
		{
			name:    "dot-relative path rejected",
			path:    "./users",
			wantErr: true,
			errMsg:  "must be an absolute path",
		},
		{
			name:    "missing directory rejected",
			path:    filepath.Join(tmp, "nope"),
			wantErr: true,
			errMsg:  "authpf.userRulesRootFolder does not exist:",
		},
		{
			name:    "file instead of directory rejected",
			path:    notADir,
			wantErr: true,
			errMsg:  "authpf.userRulesRootFolder is not a directory:",
		},
		{
			name:    "unreadable directory rejected",
			path:    unreadable,
			wantErr: true,
			errMsg:  "authpf.userRulesRootFolder is not readable:",
			skip:    os.Geteuid() == 0,
		},
		{
			name:    "stat failure is reported with the path",
			path:    filepath.Join(tmp, "bad\x00name"),
			wantErr: true,
			errMsg:  "cannot access authpf.userRulesRootFolder:",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.skip {
				t.Skip("running as root, permission bits are not enforced")
			}
			s := pathsTestServer(&config.ConfigFile{
				AuthPF: config.ConfigFileAuthPF{UserRulesRootFolder: tt.path},
			})
			err := s.validatePathsAndTLS()
			if tt.wantErr {
				require.Error(t, err, "userRulesRootFolder %q must be rejected", tt.path)
				assert.Contains(t, err.Error(), tt.errMsg)
				if len(tt.path) > 0 {
					assert.Contains(t, err.Error(), tt.path, "the error must name the offending path")
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// Finding 9: authpf.userRulesFile is a bare name, joined to the root folder and
// the user name at activation time.
func TestPathsValidateUserRulesFile(t *testing.T) {
	tests := []struct {
		name     string
		fileName string
		wantErr  bool
		errMsg   string
	}{
		{name: "shipped default", fileName: "authpf.rules"},
		{name: "plain name", fileName: "rules"},
		{name: "with underscore and digits", fileName: "user_rules_2"},
		{name: "empty value is required elsewhere", fileName: ""},
		{
			name:     "absolute path rejected",
			fileName: "/etc/pf.conf",
			wantErr:  true,
			errMsg:   "authpf.userRulesFile must be a plain file name",
		},
		{
			name:     "traversal to the real pf ruleset rejected",
			fileName: "../../etc/pf.conf",
			wantErr:  true,
			errMsg:   "authpf.userRulesFile must be a plain file name",
		},
		{
			name:     "subdirectory rejected",
			fileName: "subdir/rules",
			wantErr:  true,
			errMsg:   "authpf.userRulesFile must be a plain file name",
		},
		{
			name:     "windows separator rejected",
			fileName: `subdir\rules`,
			wantErr:  true,
			errMsg:   "authpf.userRulesFile must be a plain file name",
		},
		{
			name:     "bare parent directory rejected",
			fileName: "..",
			wantErr:  true,
			errMsg:   "authpf.userRulesFile must be a plain file name",
		},
		{
			name:     "hidden file rejected",
			fileName: ".authpf.rules",
			wantErr:  true,
			errMsg:   "authpf.userRulesFile must be a plain file name",
		},
		{
			name:     "space rejected",
			fileName: "authpf rules",
			wantErr:  true,
			errMsg:   "invalid characters found in config parameter: authpf.userRulesFile",
		},
		{
			name:     "shell metacharacter rejected",
			fileName: "rules;pfctl -F all",
			wantErr:  true,
			errMsg:   "invalid characters found in config parameter: authpf.userRulesFile",
		},
		{
			name:     "non ASCII rejected",
			fileName: "rulesä",
			wantErr:  true,
			errMsg:   "invalid characters found in config parameter: authpf.userRulesFile",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := pathsTestServer(&config.ConfigFile{
				AuthPF: config.ConfigFileAuthPF{UserRulesFile: tt.fileName},
			})
			err := s.validatePathsAndTLS()
			if tt.wantErr {
				require.Error(t, err, "userRulesFile %q must be rejected", tt.fileName)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// Finding 10: server.bind is concatenated with the port, so it has to be a bare
// address. Checked at startup instead of inside e.Start(addr).
func TestPathsValidateBind(t *testing.T) {
	tests := []struct {
		name    string
		bind    string
		wantErr bool
		errMsg  string
	}{
		{name: "loopback IPv4, the shipped default", bind: "127.0.0.1"},
		{name: "all interfaces IPv4", bind: "0.0.0.0"},
		{name: "site local IPv4", bind: "10.0.0.5"},
		{name: "loopback IPv6", bind: "::1"},
		{name: "all interfaces IPv6", bind: "::"},
		{name: "documented IPv6", bind: "2001:db8::1"},
		{name: "bracketed IPv6, the form net.Listen needs", bind: "[::1]"},
		{name: "bracketed all interfaces IPv6", bind: "[::]"},
		{name: "localhost", bind: "localhost"},
		{name: "localhost is case insensitive", bind: "LocalHost"},
		{name: "empty value is required elsewhere", bind: ""},
		{
			name:    "hostname rejected",
			bind:    "api.example.com",
			wantErr: true,
			errMsg:  "server.bind must be an IPv4/IPv6 address or localhost, got: \"api.example.com\"",
		},
		{
			name:    "loopback hostname variant rejected",
			bind:    "localhost.localdomain",
			wantErr: true,
			errMsg:  "server.bind must be an IPv4/IPv6 address or localhost",
		},
		{
			name:    "host with port rejected",
			bind:    "127.0.0.1:8080",
			wantErr: true,
			errMsg:  "server.bind must be an IPv4/IPv6 address or localhost",
		},
		{
			name:    "hostname with port rejected",
			bind:    "localhost:8080",
			wantErr: true,
			errMsg:  "server.bind must be an IPv4/IPv6 address or localhost",
		},
		{
			name:    "CIDR rejected",
			bind:    "10.0.0.0/24",
			wantErr: true,
			errMsg:  "server.bind must be an IPv4/IPv6 address or localhost",
		},
		{
			name:    "IPv6 CIDR rejected",
			bind:    "2001:db8::/64",
			wantErr: true,
			errMsg:  "server.bind must be an IPv4/IPv6 address or localhost",
		},
		{
			name:    "leading whitespace rejected",
			bind:    " 127.0.0.1",
			wantErr: true,
			errMsg:  "server.bind must be an IPv4/IPv6 address or localhost, got: \" 127.0.0.1\"",
		},
		{
			name:    "trailing whitespace rejected",
			bind:    "::1 ",
			wantErr: true,
			errMsg:  "server.bind must be an IPv4/IPv6 address or localhost",
		},
		{name: "whitespace only rejected", bind: "   ", wantErr: true, errMsg: "server.bind must be"},
		{
			name:    "short IPv4 shorthand rejected",
			bind:    "127.1",
			wantErr: true,
			errMsg:  "server.bind must be an IPv4/IPv6 address or localhost",
		},
		{name: "octet out of range rejected", bind: "999.0.0.1", wantErr: true, errMsg: "server.bind must be"},
		{
			name:    "unmatched bracket rejected",
			bind:    "[::1",
			wantErr: true,
			errMsg:  "server.bind has an unmatched '[', got: \"[::1\"",
		},
		{name: "empty brackets rejected", bind: "[]", wantErr: true, errMsg: "server.bind must be"},
		{
			name:    "bracketed hostname rejected",
			bind:    "[localhost]",
			wantErr: true,
			errMsg:  "server.bind must be an IPv4/IPv6 address or localhost",
		},
		{
			name:    "IPv6 zone rejected",
			bind:    "fe80::1%eth0",
			wantErr: true,
			errMsg:  "server.bind must be an IPv4/IPv6 address or localhost",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := pathsTestServer(&config.ConfigFile{
				Server: config.ConfigFileServer{Bind: tt.bind},
			})
			err := s.validatePathsAndTLS()
			if tt.wantErr {
				require.Error(t, err, "bind %q must be rejected", tt.bind)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// Finding 12: server.logfile was never opened in -foreground mode.
func TestPathsValidateLogfile(t *testing.T) {
	tmp := t.TempDir()

	tests := []struct {
		name      string
		logfile   string
		prepare   func(t *testing.T)
		wantErr   bool
		errMsg    string
		wantFile  string
		inWorkDir bool
	}{
		{name: "empty value is required elsewhere", logfile: ""},
		{name: "new absolute path is created", logfile: filepath.Join(tmp, "api.log"), wantFile: filepath.Join(tmp, "api.log")},
		{name: "existing file is kept", logfile: filepath.Join(tmp, "existing.log"), wantFile: filepath.Join(tmp, "existing.log"),
			prepare: func(t *testing.T) {
				require.NoError(t, os.WriteFile(filepath.Join(tmp, "existing.log"), []byte("old\n"), 0640))
			}},
		{
			name:      "relative path is allowed",
			logfile:   "./authpf-api.log",
			inWorkDir: true,
			wantFile:  filepath.Join(tmp, "authpf-api.log"),
		},
		{
			name:    "missing parent directory is reported",
			logfile: filepath.Join(tmp, "nodir", "api.log"),
			wantErr: true,
			errMsg:  "cannot open server.logfile:",
		},
		{
			name:    "directory as logfile is reported",
			logfile: tmp,
			wantErr: true,
			errMsg:  "cannot open server.logfile:",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.inWorkDir {
				t.Chdir(tmp)
			}
			if tt.prepare != nil {
				tt.prepare(t)
			}
			s := pathsTestServer(&config.ConfigFile{
				Server: config.ConfigFileServer{Logfile: tt.logfile},
			})
			err := s.validatePathsAndTLS()
			if tt.wantErr {
				require.Error(t, err, "logfile %q must be rejected", tt.logfile)
				assert.Contains(t, err.Error(), tt.errMsg)
				assert.Contains(t, err.Error(), tt.logfile, "the error must name the offending path")
				return
			}
			require.NoError(t, err)
			if tt.wantFile != "" {
				_, statErr := os.Stat(tt.wantFile)
				assert.NoError(t, statErr, "validation must leave the logfile usable")
			}
		})
	}
}

// Finding 11: the SSL key was never checked when the certificate was empty and
// the two files were never parsed or matched against each other.
func TestSSLValidateKeyPair(t *testing.T) {
	tmp := t.TempDir()
	certA, keyA := pathsWriteKeyPair(t, tmp, "server-a")
	certB, keyB := pathsWriteKeyPair(t, tmp, "server-b")

	garbageCert := filepath.Join(tmp, "garbage.crt")
	require.NoError(t, os.WriteFile(garbageCert, []byte("not a PEM file\n"), 0640))

	missingCert := filepath.Join(tmp, "missing.crt")
	missingKey := filepath.Join(tmp, "missing.key")

	tests := []struct {
		name    string
		cert    string
		key     string
		wantErr bool
		errMsg  string
	}{
		{name: "SSL disabled, both empty", cert: "", key: ""},
		{
			name:    "key without certificate is a configuration error",
			cert:    "",
			key:     keyA,
			wantErr: true,
			errMsg:  "server.ssl.key is configured but server.ssl.certificate is empty",
		},
		{
			name:    "certificate without key is a configuration error",
			cert:    certA,
			key:     "",
			wantErr: true,
			errMsg:  "server.ssl.certificate is configured but server.ssl.key is empty",
		},
		{name: "matching pair is accepted", cert: certA, key: keyA},
		{
			name:    "key of another certificate is rejected",
			cert:    certA,
			key:     keyB,
			wantErr: true,
			errMsg:  "private key does not match public key",
		},
		{
			name:    "swapped pair is rejected",
			cert:    certB,
			key:     keyA,
			wantErr: true,
			errMsg:  "private key does not match public key",
		},
		{
			name:    "unparsable certificate is rejected",
			cert:    garbageCert,
			key:     keyA,
			wantErr: true,
			errMsg:  "invalid SSL certificate/key pair",
		},
		{
			name:    "certificate file missing keeps its message",
			cert:    missingCert,
			key:     keyA,
			wantErr: true,
			errMsg:  "SSL certificate file not found:",
		},
		{
			name:    "key file missing keeps its message",
			cert:    certA,
			key:     missingKey,
			wantErr: true,
			errMsg:  "SSL key file not found:",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateSSLFiles(tt.cert, tt.key)
			if tt.wantErr {
				require.Error(t, err, "cert %q / key %q must be rejected", tt.cert, tt.key)
				assert.Contains(t, err.Error(), tt.errMsg)
				return
			}
			assert.NoError(t, err)
		})
	}

	// The pair errors have to name both files, otherwise the operator cannot
	// tell which of the two paths is wrong.
	t.Run("pair error names both paths", func(t *testing.T) {
		err := validateSSLFiles(certA, keyB)
		require.Error(t, err)
		assert.Contains(t, err.Error(), certA)
		assert.Contains(t, err.Error(), keyB)
	})
}

// A configuration that satisfies every check must pass validateConfig(), the
// gate the server actually runs before it starts.
func TestPathsAndTLSValidateConfigAcceptsFullConfig(t *testing.T) {
	tmp := t.TempDir()
	rulesDir := filepath.Join(tmp, "users")
	require.NoError(t, os.Mkdir(rulesDir, 0750))
	cert, key := pathsWriteKeyPair(t, tmp, "full-config")
	// Sibling validators (pfctl/lifecycle) run in the same validateConfig() call,
	// so every binary/mode here is test-local and host-independent.
	pfctl := filepath.Join(tmp, "pfctl")
	require.NoError(t, os.WriteFile(pfctl, []byte("#!/bin/sh\nexit 0\n"), 0700))

	cfg := &config.ConfigFile{
		Defaults: config.ConfigFileDefaults{PfctlBinary: pfctl},
		Server: config.ConfigFileServer{
			Bind:         "127.0.0.1",
			Port:         8443,
			SSL:          config.ConfigFileServerSSL{Certificate: cert, Key: key},
			ElevatorMode: "none",
			Logfile:      filepath.Join(tmp, "authpf-api.log"),
		},
		AuthPF: config.ConfigFileAuthPF{
			Timeout:             "8m",
			UserRulesRootFolder: rulesDir,
			UserRulesFile:       "authpf.rules",
			AnchorName:          "authpf",
			FlushFilter:         []string{"rules", "nat"},
			PfTable:             "authpf_table",
			SchedulerInterval:   "60",
		},
		Rbac: validRBAC(),
	}

	s := pathsTestServer(cfg)
	assert.NoError(t, s.validateConfig())
	// validateConfig() does not cover the SSL pair, Bootstrap() calls it apart.
	assert.NoError(t, validateSSLFiles(cfg.Server.SSL.Certificate, cfg.Server.SSL.Key))
}

func PfctlConfigFixture(t *testing.T) *config.ConfigFile {
	t.Helper()
	root := t.TempDir()
	return &config.ConfigFile{
		Defaults: config.ConfigFileDefaults{PfctlBinary: "echo"},
		Server: config.ConfigFileServer{
			Bind: "127.0.0.1", Port: 8080, Logfile: filepath.Join(root, "authpf-api.log"), ElevatorMode: "none",
		},
		AuthPF: config.ConfigFileAuthPF{
			Timeout: "1h", UserRulesRootFolder: root, UserRulesFile: "rules", AnchorName: "authpf",
			FlushFilter: []string{"rules", "nat"},
		},
		Rbac: validRBAC(),
	}
}

func TestPfctlValidateLifecycleValues(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*config.ConfigFile)
		wantErr string
	}{
		{name: "empty optional values", mutate: func(c *config.ConfigFile) {
			c.Defaults.PfctlBinary = ""
			c.Server.ElevatorMode = ""
			c.AuthPF.Timeout = ""
			c.AuthPF.FlushFilter = nil
		}},
		{name: "elevator none", mutate: func(c *config.ConfigFile) { c.Server.ElevatorMode = "none" }},
		{name: "elevator sudo located", mutate: func(c *config.ConfigFile) { c.Server.ElevatorMode = "sudo" }},
		{name: "elevator doas located", mutate: func(c *config.ConfigFile) { c.Server.ElevatorMode = "doas" }},
		{name: "elevator case rejected", mutate: func(c *config.ConfigFile) { c.Server.ElevatorMode = "Sudo" }, wantErr: "allowed values are none, sudo, doas"},
		{name: "elevator trailing space rejected", mutate: func(c *config.ConfigFile) { c.Server.ElevatorMode = "sudo " }, wantErr: "allowed values are none, sudo, doas"},
		{name: "elevator abbreviation rejected", mutate: func(c *config.ConfigFile) { c.Server.ElevatorMode = "doa" }, wantErr: "allowed values are none, sudo, doas"},
		{name: "missing elevator executable", mutate: func(c *config.ConfigFile) { c.Server.ElevatorMode = "sudo" }, wantErr: "not found in PATH"},
		{name: "startup empty", mutate: func(c *config.ConfigFile) { c.AuthPF.OnStartup = "" }},
		{name: "startup none", mutate: func(c *config.ConfigFile) { c.AuthPF.OnStartup = "none" }},
		{name: "startup import", mutate: func(c *config.ConfigFile) { c.AuthPF.OnStartup = "import" }},
		{name: "startup importflush", mutate: func(c *config.ConfigFile) { c.AuthPF.OnStartup = "importflush" }},
		{name: "startup invalid", mutate: func(c *config.ConfigFile) { c.AuthPF.OnStartup = "load" }, wantErr: "allowed values are none, import, importflush"},
		{name: "shutdown empty", mutate: func(c *config.ConfigFile) { c.AuthPF.OnShutdown = "" }},
		{name: "shutdown none", mutate: func(c *config.ConfigFile) { c.AuthPF.OnShutdown = "none" }},
		{name: "shutdown flushall", mutate: func(c *config.ConfigFile) { c.AuthPF.OnShutdown = "flushall" }},
		{name: "shutdown invalid", mutate: func(c *config.ConfigFile) { c.AuthPF.OnShutdown = "flush" }, wantErr: "allowed values are none, flushall"},
		{name: "timeout minimum", mutate: func(c *config.ConfigFile) { c.AuthPF.Timeout = "1s" }},
		{name: "timeout maximum", mutate: func(c *config.ConfigFile) { c.AuthPF.Timeout = "24h" }},
		{name: "timeout malformed", mutate: func(c *config.ConfigFile) { c.AuthPF.Timeout = "banana" }, wantErr: "invalid authpf.timeout"},
		{name: "timeout invalid day unit", mutate: func(c *config.ConfigFile) { c.AuthPF.Timeout = "3d" }, wantErr: "invalid timeout format"},
		{name: "flush target nat", mutate: func(c *config.ConfigFile) { c.AuthPF.FlushFilter = []string{"nat"} }},
		{name: "flush target rules", mutate: func(c *config.ConfigFile) { c.AuthPF.FlushFilter = []string{"rules"} }},
		{name: "flush target queue", mutate: func(c *config.ConfigFile) { c.AuthPF.FlushFilter = []string{"queue"} }},
		{name: "flush target ethernet", mutate: func(c *config.ConfigFile) { c.AuthPF.FlushFilter = []string{"ethernet"} }},
		{name: "flush target states", mutate: func(c *config.ConfigFile) { c.AuthPF.FlushFilter = []string{"states"} }},
		{name: "flush target Sources rejected", mutate: func(c *config.ConfigFile) { c.AuthPF.FlushFilter = []string{"Sources"} }, wantErr: "allowed values are nat, queue, ethernet, rules, states, info, Tables, osfp, all"},
		{name: "flush target info", mutate: func(c *config.ConfigFile) { c.AuthPF.FlushFilter = []string{"info"} }},
		{name: "flush target Tables", mutate: func(c *config.ConfigFile) { c.AuthPF.FlushFilter = []string{"Tables"} }},
		{name: "flush target osfp", mutate: func(c *config.ConfigFile) { c.AuthPF.FlushFilter = []string{"osfp"} }},
		{name: "flush target Reset rejected", mutate: func(c *config.ConfigFile) { c.AuthPF.FlushFilter = []string{"Reset"} }, wantErr: "allowed values are nat, queue, ethernet, rules, states, info, Tables, osfp, all"},
		{name: "flush target all", mutate: func(c *config.ConfigFile) { c.AuthPF.FlushFilter = []string{"all"} }},
		{name: "flush unknown target lists allowed values", mutate: func(c *config.ConfigFile) { c.AuthPF.FlushFilter = []string{"filter"} }, wantErr: "allowed values are nat, queue, ethernet, rules, states, info, Tables, osfp, all"},
		{name: "flush whitespace", mutate: func(c *config.ConfigFile) { c.AuthPF.FlushFilter = []string{"rules all"} }, wantErr: "whitespace"},
		{name: "flush leading option", mutate: func(c *config.ConfigFile) { c.AuthPF.FlushFilter = []string{"-all"} }, wantErr: "leading '-'"},
		{name: "flush slash", mutate: func(c *config.ConfigFile) { c.AuthPF.FlushFilter = []string{"rules/all"} }, wantErr: "path separators"},
		{name: "flush backslash", mutate: func(c *config.ConfigFile) { c.AuthPF.FlushFilter = []string{"rules\\all"} }, wantErr: "path separators"},
		{name: "flush control", mutate: func(c *config.ConfigFile) { c.AuthPF.FlushFilter = []string{"rules\nall"} }, wantErr: "control characters"},
		{name: "pfctl binary path found", mutate: func(c *config.ConfigFile) { c.Defaults.PfctlBinary = "echo" }},
		{name: "pfctl executable relative path", mutate: func(c *config.ConfigFile) {
			path := filepath.Join(t.TempDir(), "relative-pfctl")
			require.NoError(t, os.WriteFile(path, []byte("#!/bin/sh\\nexit 0\\n"), 0700))
			cwd, err := os.Getwd()
			require.NoError(t, err)
			relativePath, err := filepath.Rel(cwd, path)
			require.NoError(t, err)
			c.Defaults.PfctlBinary = relativePath
		}},
		{name: "pfctl missing binary", mutate: func(c *config.ConfigFile) { c.Defaults.PfctlBinary = "pfctl-a-missing-binary" }, wantErr: "not found in PATH"},
		{name: "pfctl directory rejected", mutate: func(c *config.ConfigFile) { c.Defaults.PfctlBinary = t.TempDir() }, wantErr: "regular file"},
		{name: "pfctl non executable rejected", mutate: func(c *config.ConfigFile) {
			path := filepath.Join(t.TempDir(), "not-executable")
			require.NoError(t, os.WriteFile(path, []byte("data"), 0600))
			c.Defaults.PfctlBinary = path
		}, wantErr: "not executable"},
	}

	for _, tt := range tests {
		t.Run("Pfctl"+tt.name, func(t *testing.T) {
			pathDir := t.TempDir()
			for _, name := range []string{"echo", "sudo", "doas"} {
				if tt.name == "missing elevator executable" && name == "sudo" {
					continue
				}
				require.NoError(t, os.WriteFile(filepath.Join(pathDir, name), []byte("#!/bin/sh\\nexit 0\\n"), 0700))
			}
			t.Setenv("PATH", pathDir)
			cfg := PfctlConfigFixture(t)
			tt.mutate(cfg)
			s := &Server{config: cfg, logger: zerolog.Nop()}
			err := s.validatePfctlAndLifecycle()
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestPfctlValidateFullConfig(t *testing.T) {
	s := &Server{config: PfctlConfigFixture(t), logger: zerolog.Nop()}
	require.NoError(t, s.validateConfig())
}

func rbacTestServer(rbac config.ConfigFileRbac) *Server {
	return &Server{config: &config.ConfigFile{Rbac: rbac}, logger: zerolog.New(&bytes.Buffer{})}
}

func rbacTestConfig() config.ConfigFileRbac {
	return validRBAC()
}

func TestValidateRBACUsersRequired(t *testing.T) {
	for _, users := range []map[string]config.ConfigFileRbacUsers{nil, {}} {
		err := rbacTestServer(config.ConfigFileRbac{Users: users}).validateRBAC()
		assert.ErrorContains(t, err, "no users configured")
	}
}

func TestValidateRBACPermissions(t *testing.T) {
	permissions := []string{
		config.RBAC_ACTIVATE_OWN_RULE,
		config.RBAC_ACTIVATE_OTHER_RULE,
		config.RBAC_DEACTIVATE_OWN_RULE,
		config.RBAC_DEACTIVATE_OTHER_RULE,
		config.RBAC_GET_STATUS_OWN_RULE,
		config.RBAC_GET_STATUS_OTHER_RULE,
	}
	for _, permission := range permissions {
		t.Run(permission, func(t *testing.T) {
			rbac := rbacTestConfig()
			rbac.Roles["admin"] = config.ConfigFileRbacRoles{Permissions: []string{permission}}
			assert.NoError(t, rbacTestServer(rbac).validateRBAC())
		})
	}

	rbac := rbacTestConfig()
	rbac.Roles["viewers"] = config.ConfigFileRbacRoles{Permissions: []string{"view_own_rule"}}
	err := rbacTestServer(rbac).validateRBAC()
	assert.ErrorContains(t, err, "viewers")
	assert.ErrorContains(t, err, "view_own_rule")
	for _, permission := range permissions {
		assert.Contains(t, err.Error(), permission)
	}

	rbac = rbacTestConfig()
	rbac.Roles["admin"] = config.ConfigFileRbacRoles{}
	assert.NoError(t, rbacTestServer(rbac).validateRBAC(), "empty permission lists are legal")
	rbac.Roles["admin"] = config.ConfigFileRbacRoles{Permissions: []string{permissions[0], permissions[0]}}
	assert.NoError(t, rbacTestServer(rbac).validateRBAC(), "duplicate permissions are allowed and harmless")
}

func TestValidateRBACUserRole(t *testing.T) {
	for _, role := range []string{"", "missing"} {
		t.Run("role_"+role, func(t *testing.T) {
			rbac := rbacTestConfig()
			rbac.Users["alice"] = rbac.Users["admin"]
			user := rbac.Users["alice"]
			user.Role = role
			rbac.Users["alice"] = user
			err := rbacTestServer(rbac).validateRBAC()
			assert.Error(t, err)
			assert.ErrorContains(t, err, "alice")
			if role != "" {
				assert.ErrorContains(t, err, role)
			}
		})
	}
}

func TestValidateRBACPassword(t *testing.T) {
	for _, tt := range []struct {
		name     string
		password string
		wantErr  bool
	}{
		{name: "empty", password: "", wantErr: true},
		{name: "plaintext", password: "not-a-hash", wantErr: true},
		{name: "truncated", password: fixturePasswordHash[:30], wantErr: true},
		{name: "malformed bcrypt encoding", password: "$2a$10$!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!", wantErr: true},
		{name: "unsupported cost", password: "$2a$99$" + fixturePasswordHash[7:], wantErr: true},
		{name: "valid bcrypt", password: fixturePasswordHash},
	} {
		t.Run(tt.name, func(t *testing.T) {
			rbac := rbacTestConfig()
			user := rbac.Users["admin"]
			user.Password = tt.password
			rbac.Users["admin"] = user
			err := rbacTestServer(rbac).validateRBAC()
			if tt.wantErr {
				require.Error(t, err)
				assert.ErrorContains(t, err, "admin")
				if tt.password != "" {
					assert.NotContains(t, err.Error(), tt.password)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateRBACUserIDs(t *testing.T) {
	for _, id := range []int{0, 10} {
		rbac := rbacTestConfig()
		user := rbac.Users["admin"]
		user.UserID = id
		rbac.Users["admin"] = user
		assert.NoError(t, rbacTestServer(rbac).validateRBAC())
	}

	rbac := rbacTestConfig()
	user := rbac.Users["admin"]
	user.UserID = -1
	rbac.Users["admin"] = user
	assert.ErrorContains(t, rbacTestServer(rbac).validateRBAC(), "must not be negative")

	rbac = rbacTestConfig()
	rbac.Users["alice"] = rbac.Users["admin"]
	err := rbacTestServer(rbac).validateRBAC()
	require.Error(t, err)
	assert.ErrorContains(t, err, "alice")
	assert.ErrorContains(t, err, "admin")
	assert.ErrorContains(t, err, "1000")
}

func TestValidateRBACUsernames(t *testing.T) {
	for _, tt := range []struct {
		name     string
		username string
		wantErr  bool
	}{
		{name: "valid", username: "A_user-9"},
		{name: "empty", username: "", wantErr: true},
		{name: "256 characters", username: strings.Repeat("a", 256), wantErr: true},
		{name: "slash", username: "../evil", wantErr: true},
		{name: "dots", username: "..", wantErr: true},
		{name: "space", username: "a b", wantErr: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			rbac := rbacTestConfig()
			rbac.Users = map[string]config.ConfigFileRbacUsers{tt.username: rbac.Users["admin"]}
			err := rbacTestServer(rbac).validateRBAC()
			if tt.wantErr {
				assert.Error(t, err)
				assert.ErrorContains(t, err, "invalid username")
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateConfigRBACFullConfig(t *testing.T) {
	// Environment-neutral paths: every path here is created for this test, so the
	// pfctl/path checks of the sibling validators cannot depend on the host OS.
	dir := t.TempDir()
	pfctl := filepath.Join(dir, "pfctl")
	require.NoError(t, os.WriteFile(pfctl, []byte("#!/bin/sh\nexit 0\n"), 0700))
	rbac := validRBAC()
	s := &Server{
		logger: zerolog.New(&bytes.Buffer{}),
		config: &config.ConfigFile{
			Defaults: config.ConfigFileDefaults{PfctlBinary: pfctl},
			Server: config.ConfigFileServer{Bind: "127.0.0.1", Port: 8080,
				Logfile: filepath.Join(dir, "authpf-api.log"), ElevatorMode: "none"},
			AuthPF: config.ConfigFileAuthPF{
				Timeout: "1h", UserRulesRootFolder: dir, UserRulesFile: "rules", AnchorName: "authpf", FlushFilter: []string{"nat"},
			},
			Rbac: rbac,
		},
	}
	assert.NoError(t, s.validateConfig())
}
