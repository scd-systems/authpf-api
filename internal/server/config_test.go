package server

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/scd-systems/authpf-api/pkg/config"
)

func TestValidateMacroKey(t *testing.T) {
	tests := []struct {
		name    string
		user    config.ConfigFileRbacUsers
		key     string
		wantErr bool
		errMsg  string
	}{
		{
			name: "no conflict: key is user_ip but UserIP is empty",
			user: config.ConfigFileRbacUsers{
				UserIP: "",
				Macros: map[string]string{"user_ip": "10.0.0.1"},
			},
			key:     "user_ip",
			wantErr: false,
		},
		{
			name: "no conflict: UserIP set but key is not user_ip",
			user: config.ConfigFileRbacUsers{
				UserIP: "192.168.1.1",
				Macros: map[string]string{"my_macro": "value"},
			},
			key:     "my_macro",
			wantErr: false,
		},
		{
			name: "conflict: UserIP set and key is user_ip",
			user: config.ConfigFileRbacUsers{
				UserIP: "192.168.1.1",
				Macros: map[string]string{"user_ip": "10.0.0.1"},
			},
			key:     "user_ip",
			wantErr: true,
			errMsg:  "userIp and macro user_ip defined (same)",
		},
		{
			name: "no conflict: both UserIP and key are empty",
			user: config.ConfigFileRbacUsers{
				UserIP: "",
				Macros: map[string]string{},
			},
			key:     "",
			wantErr: false,
		},
		{
			name: "no conflict: key is empty, UserIP is set",
			user: config.ConfigFileRbacUsers{
				UserIP: "10.0.0.1",
				Macros: map[string]string{},
			},
			key:     "",
			wantErr: false,
		},
		{
			name: "no conflict: key USER_IP is case-sensitive, UserIP is set",
			user: config.ConfigFileRbacUsers{
				UserIP: "10.0.0.1",
				Macros: map[string]string{"USER_IP": "value"},
			},
			key:     "USER_IP",
			wantErr: false,
		},
		{
			name: "no conflict: key User_Ip mixed case, UserIP is set",
			user: config.ConfigFileRbacUsers{
				UserIP: "10.0.0.1",
				Macros: map[string]string{"User_Ip": "value"},
			},
			key:     "User_Ip",
			wantErr: false,
		},
		{
			name: "conflict: UserID set and key is user_id",
			user: config.ConfigFileRbacUsers{
				UserID: 1000,
				Macros: map[string]string{"user_id": "1000"},
			},
			key:     "user_id",
			wantErr: true,
			errMsg:  "userId and macro user_id defined (same)",
		},
		{
			name: "no conflict: key user_id but UserID is zero",
			user: config.ConfigFileRbacUsers{
				UserID: 0,
				Macros: map[string]string{"user_id": "0"},
			},
			key:     "user_id",
			wantErr: false,
		},
		{
			name: "no conflict: key User_Id mixed case, UserID is set (case-sensitive)",
			user: config.ConfigFileRbacUsers{
				UserID: 1000,
				Macros: map[string]string{"User_Id": "1000"},
			},
			key:     "User_Id",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateMacroKey(tt.user, tt.key)
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
			errMsg:  "invalid characters found in macro",
		},
		{
			name:    "contains hyphen",
			value:   "hello-world",
			wantErr: true,
			errMsg:  "invalid characters found in macro",
		},
		{
			name:    "contains slash",
			value:   "hello/world",
			wantErr: true,
			errMsg:  "invalid characters found in macro",
		},
		{
			name:    "contains at-sign",
			value:   "user@host",
			wantErr: true,
			errMsg:  "invalid characters found in macro",
		},
		{
			name:    "contains unicode character",
			value:   "héllo",
			wantErr: true,
			errMsg:  "invalid characters found in macro",
		},
		{
			name:    "contains semicolon",
			value:   "val;ue",
			wantErr: true,
			errMsg:  "invalid characters found in macro",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateAlphanumericASCII(tt.value)
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
	result := collectRequiredPfTables(cfg)
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
	result := collectRequiredPfTables(cfg)
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
	result := collectRequiredPfTables(cfg)
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
	result := collectRequiredPfTables(cfg)
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
	result := collectRequiredPfTables(cfg)
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
	result := collectRequiredPfTables(cfg)
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
	result := collectRequiredPfTables(cfg)
	assert.Equal(t, []string{"global_table"}, result)
}
