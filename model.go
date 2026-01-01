package main

import (
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// AuthPFRule represents a rule that can be loaded into FreeBSD authpf.
type AuthPFRule struct {
	Username  string    `json:"username"`
	Timeout   string    `json:"timeout,omitempty"`
	ClientIP  string    `json:"client_ip"`
	ClientID  int       `json:"client_id"`
	ExpiresAt time.Time `json:"expireat"`
}

// JWTClaims represents the JWT token claims
type JWTClaims struct {
	Username string `json:"username"`
	jwt.RegisteredClaims
}

// LoginRequest represents the login request payload
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// LoginResponse represents the login response with token
type LoginResponse struct {
	Token string `json:"token"`
}

type SystemCommandResult struct {
	Command  string
	Stdout   string
	Stderr   string
	ExitCode int
	Error    error
}

// Global variables
var (
	rules     = map[string]*AuthPFRule{}
	lock      = sync.Mutex{}
	jwtSecret = []byte("your-secret-key-change-in-production")
)
