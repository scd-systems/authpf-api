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

type ConfigFile struct {
	Defaults ConfigFileDefaults `yaml:"defaults"`
	Server   ConfigFileServer   `yaml:"server"`
	AuthPF   ConfigFileAuthPF   `yaml:"authpf"`
	Rbac     ConfigFileRbac     `yaml:"rbac"`
}

type ConfigFileDefaults struct {
	Timeout             string `yaml:"timeout"`
	UserRulesRootFolder string `yaml:"userRulesRootFolder"`
	UserRulesFile       string `yaml:"userRulesFile"`
	PfctlBinary         string `yaml:"pfctlBinary"`
}

type ConfigFileAuthPF struct {
	ClientID      string `yaml:"clientID"`
	AnchorName    string `yaml:"anchorName"`
	TableName     string `yaml:"tableName"`
	MultiClientIP bool   `yaml:"multiClientIP"`
}

type ConfigFileServer struct {
	Bind         string              `yaml:"bind"`
	Port         uint16              `yaml:"port"`
	SSL          ConfigFileServerSSL `yaml:"ssl"`
	ElevatorMode string              `yaml:"elevatorMode"`
}

type ConfigFileServerSSL struct {
	Certificate string `yaml:"certificate"`
	Key         string `yaml:"key"`
}

type ConfigFileRbac struct {
	Roles map[string]ConfigFileRbacRoles `yaml:"roles"`
	Users map[string]ConfigFileRbacUsers `yaml:"users"`
}

type ConfigFileRbacRoles struct {
	Permissions []string `yaml:"permissions"`
}

type ConfigFileRbacUsers struct {
	UserRulesFile string `yaml:"userRulesFile"`
	Password      string `yaml:"password"`
	Role          string `yaml:"role"`
}

const (
	CONFIG_FILE                = "/usr/local/etc/authpf-api-config.yaml"
	RBAC_ACTIVATE_RULE         = "set_rules"
	RBAC_DEACTIVATE_OWN_RULE   = "delete_own_rule"
	RBAC_DEACTIVATE_OTHER_RULE = "delete_other_rule"
	RBAC_GET_STATUS_OWN_RULE   = "view_own_rule"
	RBAC_GET_STATUS_OTHER_RULE = "view_other_rule"
	PERM_INVALID               = iota
	PERM_VALID
)

// Global variables
var (
	rules     = map[string]*AuthPFRule{}
	lock      = sync.Mutex{}
	jwtSecret = []byte("your-secret-key-change-in-production")
	config    ConfigFile
)
