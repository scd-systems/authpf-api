package config

const (
	CONFIG_FILE                = "/usr/local/etc/authpf-api.conf"
	RBAC_ACTIVATE_OWN_RULE     = "activate_own_rules"
	RBAC_ACTIVATE_OTHER_RULE   = "activate_other_rules"
	RBAC_DEACTIVATE_OWN_RULE   = "deactivate_own_rules"
	RBAC_DEACTIVATE_OTHER_RULE = "deactivate_other_rules"
	RBAC_GET_STATUS_OWN_RULE   = "view_own_rules"
	RBAC_GET_STATUS_OTHER_RULE = "view_other_rules"
	SESSION_REGISTER           = "activate"
	SESSION_UNREGISTER         = "deactivate"
	SESSION_VIEW               = "view"
)

type ConfigFile struct {
	Defaults ConfigFileDefaults `yaml:"defaults"`
	Server   ConfigFileServer   `yaml:"server"`
	AuthPF   ConfigFileAuthPF   `yaml:"authpf"`
	Rbac     ConfigFileRbac     `yaml:"rbac"`
}

type ConfigFileDefaults struct {
	PfctlBinary string `yaml:"pfctlBinary"`
}

type ConfigFileAuthPF struct {
	Timeout             string   `yaml:"timeout"`
	UserRulesRootFolder string   `yaml:"userRulesRootFolder"`
	UserRulesFile       string   `yaml:"userRulesFile"`
	AnchorName          string   `yaml:"anchorName"`
	FlushFilter         []string `yaml:"flushFilter"`
	OnShutdown          string   `yaml:"onShutdown"`
	OnStartup           string   `yaml:"onStartup"`
	PfTable             string   `yaml:"pfTable"`
}

type ConfigFileServer struct {
	Bind            string              `yaml:"bind"`
	Port            uint16              `yaml:"port"`
	SSL             ConfigFileServerSSL `yaml:"ssl"`
	ElevatorMode    string              `yaml:"elevatorMode"`
	Logfile         string              `yaml:"logfile"`
	JwtTokenTimeout string              `yaml:"jwtTokenTimeout"`
	JwtSecret       string              `yaml:"jwtSecret,omitempty"`
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
	UserRulesFile string            `yaml:"userRulesFile"`
	Password      string            `yaml:"password"`
	Role          string            `yaml:"role"`
	UserID        int               `yaml:"userId,omitempty"`
	UserIP        string            `yaml:"userIp,omitempty"`
	Macros        map[string]string `yaml:"macros"`
	PfTable       string            `yaml:"pfTable"`
}
