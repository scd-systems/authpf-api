package main

import (
	"testing"
)

// TestValidateAnchor tests anchor name validation
func TestValidateAnchor(t *testing.T) {
	tests := []struct {
		name    string
		anchor  string
		wantErr bool
	}{
		{
			name:    "valid anchor",
			anchor:  "authpf/testuser(1000)",
			wantErr: false,
		},
		{
			name:    "valid anchor with dots",
			anchor:  "authpf/test.user(1000)",
			wantErr: false,
		},
		{
			name:    "valid anchor with underscores",
			anchor:  "authpf/test_user(1000)",
			wantErr: false,
		},
		{
			name:    "valid anchor with hyphens",
			anchor:  "authpf/test-user(1000)",
			wantErr: false,
		},
		{
			name:    "invalid prefix",
			anchor:  "sudo/testuser(1000)",
			wantErr: true,
		},
		{
			name:    "missing parentheses",
			anchor:  "authpf/testuser1000",
			wantErr: true,
		},
		{
			name:    "non-numeric uid",
			anchor:  "authpf/testuser(abc)",
			wantErr: true,
		},
		{
			name:    "negative uid",
			anchor:  "authpf/testuser(-1)",
			wantErr: true,
		},
		{
			name:    "uid too large",
			anchor:  "authpf/testuser(2147483648)",
			wantErr: true,
		},
		{
			name:    "empty username",
			anchor:  "authpf/(1000)",
			wantErr: true,
		},
		{
			name:    "username too long",
			anchor:  "authpf/verylongusernamethatexceedsthirtytwocharacterlimit(1000)",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateAnchor(tt.anchor)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateAnchor() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestValidateIP tests IP address validation
func TestValidateIP(t *testing.T) {
	tests := []struct {
		name    string
		ip      string
		wantErr bool
	}{
		{
			name:    "valid ipv4",
			ip:      "192.168.1.1",
			wantErr: false,
		},
		{
			name:    "valid ipv4 localhost",
			ip:      "127.0.0.1",
			wantErr: false,
		},
		{
			name:    "valid ipv6",
			ip:      "2001:db8::1",
			wantErr: false,
		},
		{
			name:    "valid ipv6 localhost",
			ip:      "::1",
			wantErr: false,
		},
		{
			name:    "invalid ip",
			ip:      "256.256.256.256",
			wantErr: true,
		},
		{
			name:    "invalid format",
			ip:      "not.an.ip.address",
			wantErr: true,
		},
		{
			name:    "empty string",
			ip:      "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateIP(tt.ip)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateIP() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestValidateDefine tests define parameter validation
func TestValidateDefine(t *testing.T) {
	tests := []struct {
		name    string
		define  string
		wantErr bool
	}{
		{
			name:    "valid user_ip",
			define:  "user_ip=192.168.1.1",
			wantErr: false,
		},
		{
			name:    "valid user_id",
			define:  "user_id=1000",
			wantErr: false,
		},
		{
			name:    "invalid key",
			define:  "invalid_key=value",
			wantErr: true,
		},
		{
			name:    "invalid ip value",
			define:  "user_ip=256.256.256.256",
			wantErr: true,
		},
		{
			name:    "non-numeric user_id",
			define:  "user_id=abc",
			wantErr: true,
		},
		{
			name:    "missing equals",
			define:  "user_ip192.168.1.1",
			wantErr: true,
		},
		{
			name:    "empty value",
			define:  "user_ip=",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateDefine(tt.define)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateDefine() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestValidateFilterType tests filter type validation
func TestValidateFilterType(t *testing.T) {
	tests := []struct {
		name    string
		filter  string
		wantErr bool
	}{
		{
			name:    "valid filter rules",
			filter:  "rules",
			wantErr: false,
		},
		{
			name:    "valid filter nat",
			filter:  "nat",
			wantErr: false,
		},
		{
			name:    "valid filter rdr",
			filter:  "rdr",
			wantErr: false,
		},
		{
			name:    "valid filter all",
			filter:  "all",
			wantErr: false,
		},
		{
			name:    "invalid filter",
			filter:  "invalid",
			wantErr: true,
		},
		{
			name:    "filter with special chars",
			filter:  "rules;rm -rf /",
			wantErr: true,
		},
		{
			name:    "empty filter",
			filter:  "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateFilterType(tt.filter)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateFilterType() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
