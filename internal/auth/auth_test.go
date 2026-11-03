package auth

import (
	"fmt"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/rs/zerolog"
	"github.com/scd-systems/authpf-api/pkg/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestValidateJWTClaims tests the validateJWTClaims method with various scenarios
func TestValidateJWTClaims(t *testing.T) {
	// Setup logger
	logger := zerolog.New(nil)

	// Setup config with test users
	cfg := &config.ConfigFile{
		Rbac: config.ConfigFileRbac{
			Users: map[string]config.ConfigFileRbacUsers{
				"testuser": {
					Password: "hashedpassword",
					Role:     "admin",
					UserID:   1001,
				},
				"validuser": {
					Password: "hashedpassword",
					Role:     "user",
					UserID:   1002,
				},
			},
		},
	}

	auth := &Auth{
		config: cfg,
		logger: logger,
	}

	tests := []struct {
		name        string
		claims      *JWTClaims
		clientIP    string
		expectError bool
		errorMsg    string
	}{
		{
			name: "Valid claims with all required fields",
			claims: &JWTClaims{
				Username: "testuser",
				RegisteredClaims: jwt.RegisteredClaims{
					ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
					IssuedAt:  jwt.NewNumericDate(time.Now()),
					NotBefore: jwt.NewNumericDate(time.Now()),
					Issuer:    "authpf-api",
				},
			},
			clientIP:    "192.168.1.1",
			expectError: false,
		},
		{
			name: "Valid claims without NotBefore",
			claims: &JWTClaims{
				Username: "validuser",
				RegisteredClaims: jwt.RegisteredClaims{
					ExpiresAt: jwt.NewNumericDate(time.Now().Add(2 * time.Hour)),
					IssuedAt:  jwt.NewNumericDate(time.Now()),
					Issuer:    "authpf-api",
				},
			},
			clientIP:    "10.0.0.1",
			expectError: false,
		},
		{
			name: "Empty username",
			claims: &JWTClaims{
				Username: "",
				RegisteredClaims: jwt.RegisteredClaims{
					ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
					IssuedAt:  jwt.NewNumericDate(time.Now()),
				},
			},
			clientIP:    "192.168.1.1",
			expectError: true,
			errorMsg:    "invalid username in token",
		},
		{
			name: "Username too long (> 255 characters)",
			claims: &JWTClaims{
				Username: string(make([]byte, 256)),
				RegisteredClaims: jwt.RegisteredClaims{
					ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
					IssuedAt:  jwt.NewNumericDate(time.Now()),
				},
			},
			clientIP:    "192.168.1.1",
			expectError: true,
			errorMsg:    "invalid username in token",
		},
		{
			name: "Expired token",
			claims: &JWTClaims{
				Username: "testuser",
				RegisteredClaims: jwt.RegisteredClaims{
					ExpiresAt: jwt.NewNumericDate(time.Now().Add(-1 * time.Hour)),
					IssuedAt:  jwt.NewNumericDate(time.Now().Add(-2 * time.Hour)),
				},
			},
			clientIP:    "192.168.1.1",
			expectError: true,
			errorMsg:    "token expired",
		},
		{
			name: "Missing expiration",
			claims: &JWTClaims{
				Username: "testuser",
				RegisteredClaims: jwt.RegisteredClaims{
					IssuedAt: jwt.NewNumericDate(time.Now()),
				},
			},
			clientIP:    "192.168.1.1",
			expectError: true,
			errorMsg:    "missing expiration",
		},
		{
			name: "Token issued in the future (> 60 seconds)",
			claims: &JWTClaims{
				Username: "testuser",
				RegisteredClaims: jwt.RegisteredClaims{
					ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
					IssuedAt:  jwt.NewNumericDate(time.Now().Add(2 * time.Minute)),
				},
			},
			clientIP:    "192.168.1.1",
			expectError: true,
			errorMsg:    "issued in future",
		},
		{
			name: "Token issued in the future (within 60 seconds tolerance)",
			claims: &JWTClaims{
				Username: "testuser",
				RegisteredClaims: jwt.RegisteredClaims{
					ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
					IssuedAt:  jwt.NewNumericDate(time.Now().Add(30 * time.Second)),
					Issuer:    "authpf-api",
				},
			},
			clientIP:    "192.168.1.1",
			expectError: false,
		},
		{
			name: "NotBefore in the future (> 60 seconds)",
			claims: &JWTClaims{
				Username: "testuser",
				RegisteredClaims: jwt.RegisteredClaims{
					ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
					IssuedAt:  jwt.NewNumericDate(time.Now()),
					NotBefore: jwt.NewNumericDate(time.Now().Add(2 * time.Minute)),
				},
			},
			clientIP:    "192.168.1.1",
			expectError: true,
			errorMsg:    "not yet valid",
		},
		{
			name: "NotBefore in the future (within 60 seconds tolerance)",
			claims: &JWTClaims{
				Username: "testuser",
				RegisteredClaims: jwt.RegisteredClaims{
					ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
					IssuedAt:  jwt.NewNumericDate(time.Now()),
					NotBefore: jwt.NewNumericDate(time.Now().Add(30 * time.Second)),
					Issuer:    "authpf-api",
				},
			},
			clientIP:    "192.168.1.1",
			expectError: false,
		},
		{
			name: "User not found in configuration",
			claims: &JWTClaims{
				Username: "nonexistentuser",
				RegisteredClaims: jwt.RegisteredClaims{
					ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
					IssuedAt:  jwt.NewNumericDate(time.Now()),
					Issuer:    "authpf-api",
				},
			},
			clientIP:    "192.168.1.1",
			expectError: true,
			errorMsg:    "user not found",
		},
		{
			name: "Valid token with minimal claims",
			claims: &JWTClaims{
				Username: "validuser",
				RegisteredClaims: jwt.RegisteredClaims{
					ExpiresAt: jwt.NewNumericDate(time.Now().Add(30 * time.Minute)),
					IssuedAt:  jwt.NewNumericDate(time.Now()),
					Issuer:    "authpf-api",
				},
			},
			clientIP:    "172.16.0.1",
			expectError: false,
		},
		{
			name: "Token expiring very soon (1 second)",
			claims: &JWTClaims{
				Username: "testuser",
				RegisteredClaims: jwt.RegisteredClaims{
					ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Second)),
					IssuedAt:  jwt.NewNumericDate(time.Now()),
					Issuer:    "authpf-api",
				},
			},
			clientIP:    "192.168.1.1",
			expectError: false,
		},
		{
			name: "Token with very long expiration (30 days)",
			claims: &JWTClaims{
				Username: "testuser",
				RegisteredClaims: jwt.RegisteredClaims{
					ExpiresAt: jwt.NewNumericDate(time.Now().Add(30 * 24 * time.Hour)),
					IssuedAt:  jwt.NewNumericDate(time.Now()),
					Issuer:    "authpf-api",
				},
			},
			clientIP:    "192.168.1.1",
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := auth.validateJWTClaims(tt.claims, tt.clientIP)

			if tt.expectError {
				assert.Error(t, err, "expected error but got none")
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg, "error message should contain expected text")
				}
			} else {
				assert.NoError(t, err, "expected no error but got: %v", err)
			}
		})
	}
}

// TestValidateJWTClaimsEdgeCases tests edge cases and boundary conditions
func TestValidateJWTClaimsEdgeCases(t *testing.T) {
	logger := zerolog.New(nil)

	cfg := &config.ConfigFile{
		Rbac: config.ConfigFileRbac{
			Users: map[string]config.ConfigFileRbacUsers{
				"user": {
					Password: "hash",
					Role:     "admin",
					UserID:   1,
				},
			},
		},
	}

	auth := &Auth{
		config: cfg,
		logger: logger,
	}

	tests := []struct {
		name        string
		claims      *JWTClaims
		clientIP    string
		expectError bool
		description string
	}{
		{
			name: "Username with exactly 255 characters",
			claims: &JWTClaims{
				Username: string(make([]byte, 255)),
				RegisteredClaims: jwt.RegisteredClaims{
					ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
					IssuedAt:  jwt.NewNumericDate(time.Now()),
					Issuer:    "authpf-api",
				},
			},
			clientIP:    "192.168.1.1",
			expectError: true,
			description: "Should reject username with exactly 255 null characters (not a valid user)",
		},
		{
			name: "Expiration exactly at current time",
			claims: &JWTClaims{
				Username: "user",
				RegisteredClaims: jwt.RegisteredClaims{
					ExpiresAt: jwt.NewNumericDate(time.Now()),
					IssuedAt:  jwt.NewNumericDate(time.Now().Add(-1 * time.Second)),
					Issuer:    "authpf-api",
				},
			},
			clientIP:    "192.168.1.1",
			expectError: true,
			description: "Should reject token expiring at current time",
		},
		{
			name: "IssuedAt exactly at current time",
			claims: &JWTClaims{
				Username: "user",
				RegisteredClaims: jwt.RegisteredClaims{
					ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
					IssuedAt:  jwt.NewNumericDate(time.Now()),
					Issuer:    "authpf-api",
				},
			},
			clientIP:    "192.168.1.1",
			expectError: false,
			description: "Should accept token issued at current time",
		},
		{
			name: "NotBefore exactly at current time",
			claims: &JWTClaims{
				Username: "user",
				RegisteredClaims: jwt.RegisteredClaims{
					ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
					IssuedAt:  jwt.NewNumericDate(time.Now()),
					NotBefore: jwt.NewNumericDate(time.Now()),
					Issuer:    "authpf-api",
				},
			},
			clientIP:    "192.168.1.1",
			expectError: false,
			description: "Should accept token with NotBefore at current time",
		},
		{
			name: "IPv6 address",
			claims: &JWTClaims{
				Username: "user",
				RegisteredClaims: jwt.RegisteredClaims{
					ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
					IssuedAt:  jwt.NewNumericDate(time.Now()),
					Issuer:    "authpf-api",
				},
			},
			clientIP:    "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
			expectError: false,
			description: "Should accept IPv6 addresses",
		},
		{
			name: "Localhost IPv4",
			claims: &JWTClaims{
				Username: "user",
				RegisteredClaims: jwt.RegisteredClaims{
					ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
					IssuedAt:  jwt.NewNumericDate(time.Now()),
					Issuer:    "authpf-api",
				},
			},
			clientIP:    "127.0.0.1",
			expectError: false,
			description: "Should accept localhost IPv4",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := auth.validateJWTClaims(tt.claims, tt.clientIP)

			if tt.expectError {
				assert.Error(t, err, tt.description)
			} else {
				assert.NoError(t, err, tt.description)
			}
		})
	}
}

// TestValidateJWTClaimsWithNilPointers tests handling of nil pointers in claims
func TestValidateJWTClaimsWithNilPointers(t *testing.T) {
	logger := zerolog.New(nil)

	cfg := &config.ConfigFile{
		Rbac: config.ConfigFileRbac{
			Users: map[string]config.ConfigFileRbacUsers{
				"user": {
					Password: "hash",
					Role:     "admin",
					UserID:   1,
				},
			},
		},
	}

	auth := &Auth{
		config: cfg,
		logger: logger,
	}

	tests := []struct {
		name        string
		claims      *JWTClaims
		clientIP    string
		expectError bool
		description string
	}{
		{
			name: "Nil ExpiresAt",
			claims: &JWTClaims{
				Username: "user",
				RegisteredClaims: jwt.RegisteredClaims{
					ExpiresAt: nil,
					IssuedAt:  jwt.NewNumericDate(time.Now()),
					Issuer:    "authpf-api",
				},
			},
			clientIP:    "192.168.1.1",
			expectError: true,
			description: "Should reject token with nil ExpiresAt",
		},
		{
			name: "Nil IssuedAt (allowed)",
			claims: &JWTClaims{
				Username: "user",
				RegisteredClaims: jwt.RegisteredClaims{
					ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
					IssuedAt:  nil,
					Issuer:    "authpf-api",
				},
			},
			clientIP:    "192.168.1.1",
			expectError: false,
			description: "Should accept token with nil IssuedAt",
		},
		{
			name: "Nil NotBefore (allowed)",
			claims: &JWTClaims{
				Username: "user",
				RegisteredClaims: jwt.RegisteredClaims{
					ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
					IssuedAt:  jwt.NewNumericDate(time.Now()),
					NotBefore: nil,
					Issuer:    "authpf-api",
				},
			},
			clientIP:    "192.168.1.1",
			expectError: false,
			description: "Should accept token with nil NotBefore",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := auth.validateJWTClaims(tt.claims, tt.clientIP)

			if tt.expectError {
				assert.Error(t, err, tt.description)
			} else {
				assert.NoError(t, err, tt.description)
			}
		})
	}
}

// BenchmarkValidateJWTClaims benchmarks the validateJWTClaims method
func BenchmarkValidateJWTClaims(b *testing.B) {
	logger := zerolog.New(nil)

	cfg := &config.ConfigFile{
		Rbac: config.ConfigFileRbac{
			Users: map[string]config.ConfigFileRbacUsers{
				"testuser": {
					Password: "hash",
					Role:     "admin",
					UserID:   1001,
				},
			},
		},
	}

	auth := &Auth{
		config: cfg,
		logger: logger,
	}

	claims := &JWTClaims{
		Username: "testuser",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = auth.validateJWTClaims(claims, "192.168.1.1")
	}
}

// TestValidateJWTClaimsPerformance tests performance with many users in config
func TestValidateJWTClaimsPerformance(t *testing.T) {
	logger := zerolog.New(nil)

	// Create config with many users
	users := make(map[string]config.ConfigFileRbacUsers)
	for i := 0; i < 1000; i++ {
		username := "user" + fmt.Sprintf("%d", i)
		users[username] = config.ConfigFileRbacUsers{
			Password: "hash",
			Role:     "user",
			UserID:   i + 1,
		}
	}
	users["testuser"] = config.ConfigFileRbacUsers{
		Password: "hash",
		Role:     "admin",
		UserID:   9999,
	}

	cfg := &config.ConfigFile{
		Rbac: config.ConfigFileRbac{
			Users: users,
		},
	}

	auth := &Auth{
		config: cfg,
		logger: logger,
	}

	claims := &JWTClaims{
		Username: "testuser",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "authpf-api",
		},
	}

	start := time.Now()
	err := auth.validateJWTClaims(claims, "192.168.1.1")
	duration := time.Since(start)

	require.NoError(t, err)
	assert.Less(t, duration, 100*time.Millisecond, "validation should complete within 100ms even with 1000 users")
}

// TestValidateJWTClaimsSecurityScenarios tests security-related scenarios
func TestValidateJWTClaimsSecurityScenarios(t *testing.T) {
	logger := zerolog.New(nil)

	cfg := &config.ConfigFile{
		Rbac: config.ConfigFileRbac{
			Users: map[string]config.ConfigFileRbacUsers{
				"admin": {
					Password: "hash",
					Role:     "admin",
					UserID:   1,
				},
				"user": {
					Password: "hash",
					Role:     "user",
					UserID:   2,
				},
			},
		},
	}

	auth := &Auth{
		config: cfg,
		logger: logger,
	}

	tests := []struct {
		name        string
		claims      *JWTClaims
		clientIP    string
		expectError bool
		description string
	}{
		{
			name: "Token reused after expiration",
			claims: &JWTClaims{
				Username: "admin",
				RegisteredClaims: jwt.RegisteredClaims{
					ExpiresAt: jwt.NewNumericDate(time.Now().Add(-5 * time.Minute)),
					IssuedAt:  jwt.NewNumericDate(time.Now().Add(-10 * time.Minute)),
				},
			},
			clientIP:    "192.168.1.1",
			expectError: true,
			description: "Should reject expired tokens",
		},
		{
			name: "Token with future IssuedAt (clock skew attack)",
			claims: &JWTClaims{
				Username: "admin",
				RegisteredClaims: jwt.RegisteredClaims{
					ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
					IssuedAt:  jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
				},
			},
			clientIP:    "192.168.1.1",
			expectError: true,
			description: "Should reject tokens with future IssuedAt",
		},
		{
			name: "Token with future NotBefore (premature use)",
			claims: &JWTClaims{
				Username: "user",
				RegisteredClaims: jwt.RegisteredClaims{
					ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
					IssuedAt:  jwt.NewNumericDate(time.Now()),
					NotBefore: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
				},
			},
			clientIP:    "192.168.1.1",
			expectError: true,
			description: "Should reject tokens used before NotBefore",
		},
		{
			name: "Token with privilege escalation attempt (non-existent user)",
			claims: &JWTClaims{
				Username: "superadmin",
				RegisteredClaims: jwt.RegisteredClaims{
					ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
					IssuedAt:  jwt.NewNumericDate(time.Now()),
				},
			},
			clientIP:    "192.168.1.1",
			expectError: true,
			description: "Should reject tokens for non-existent users",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := auth.validateJWTClaims(tt.claims, tt.clientIP)

			if tt.expectError {
				assert.Error(t, err, tt.description)
			} else {
				assert.NoError(t, err, tt.description)
			}
		})
	}
}
