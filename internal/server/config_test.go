package server

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

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
