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
	UserIP    string    `json:"user_ip"`
	UserID    int       `json:"user_id"`
	ExpiresAt time.Time `json:"expire_at"`
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
	Args     []string
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
	UserID       string `yaml:"userID"`
	AnchorName   string `yaml:"anchorName"`
	TableName    string `yaml:"tableName"`
	MultiUserIP  bool   `yaml:"multiUserIP"`
	ClearOnStart bool   `yaml:"clearOnStart"`
}

type ConfigFileServer struct {
	Bind         string              `yaml:"bind"`
	Port         uint16              `yaml:"port"`
	SSL          ConfigFileServerSSL `yaml:"ssl"`
	ElevatorMode string              `yaml:"elevatorMode"`
	Logfile      string              `yaml:"logfile"`
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
	UserRulesFile string `yaml:"userRulesFile,omitempty"`
	Password      string `yaml:"password"`
	Role          string `yaml:"role"`
	UserID        int    `yaml:"userId,omitempty"`
}

const (
	CONFIG_FILE                = "/usr/local/etc/authpf-api.conf"
	RBAC_ACTIVATE_OWN_RULE     = "set_own_rules"
	RBAC_ACTIVATE_OTHER_RULE   = "set_other_rules"
	RBAC_DEACTIVATE_OWN_RULE   = "delete_own_rules"
	RBAC_DEACTIVATE_OTHER_RULE = "delete_other_rules"
	RBAC_GET_STATUS_OWN_RULE   = "view_own_rules"
	RBAC_GET_STATUS_OTHER_RULE = "view_other_rules"
	AUTHPF_ACTIVATE            = "activate"
	AUTHPF_DEACTIVATE          = "deactivate"
)

// Global variables
var (
	Version   = "dev"
	rulesdb   = map[string]*AuthPFRule{}
	lock      = sync.Mutex{}
	jwtSecret = []byte("your-secret-key-change-in-production")
	config    ConfigFile
)
