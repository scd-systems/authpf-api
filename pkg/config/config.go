package config

import (
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"golang.org/x/crypto/bcrypt"
	yaml "gopkg.in/yaml.v3"
)

// maxTokenTimeout is the longest JWT token timeout accepted from the config.
const maxTokenTimeout = 30 * 24 * time.Hour

// minJwtSecretLength is the minimum length of JWT Secret in configuration
const minJwtSecretLength = 32

// DefaultSchedulerInterval is the scheduler loop interval used when
// authpf.schedulerInterval is empty.
const DefaultSchedulerInterval = 60 * time.Second

// minSchedulerInterval is how often the scheduler may at most take the session
// DB lock and shell out to pfctl. Anything below a second only spins.
const minSchedulerInterval = time.Second

// maxSchedulerInterval is the longest accepted loop interval, mirroring the
// bound on the JWT token timeout. Above it, expired anchors would effectively
// never be revoked again.
const maxSchedulerInterval = 30 * 24 * time.Hour

// SchedulerIntervalWarnThreshold is the point where the operator is warned
// without the value being rejected: an anchor stays active up to one full
// interval past its own timeout, so a long loop makes revocations late.
const SchedulerIntervalWarnThreshold = 30 * time.Minute

// schedulerSecondsPattern matches the bare number form documented in README.md
// and authpf-api.conf.sample, where schedulerInterval: 60 means 60 seconds.
var schedulerSecondsPattern = regexp.MustCompile(`^[\d]+$`)

// tokenTimeoutPattern matches a whole number with an optional m, h or d unit.
// A missing unit means hours.
var tokenTimeoutPattern = regexp.MustCompile(`^([\d]+)([dhm]?)$`)

// The API applies the same username contract to requests in internal/api/checks.go.
var rbacUsernameRegex = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)
var rbacBcryptHashRegex = regexp.MustCompile(`^\$2[aby]\$[0-9]{2}\$[./A-Za-z0-9]{53}$`)
var rbacBcryptEncoding = base64.NewEncoding("./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789").WithPadding(base64.NoPadding)

var rbacPermissions = []string{
	RBAC_ACTIVATE_OWN_RULE,
	RBAC_ACTIVATE_OTHER_RULE,
	RBAC_DEACTIVATE_OWN_RULE,
	RBAC_DEACTIVATE_OTHER_RULE,
	RBAC_GET_STATUS_OWN_RULE,
	RBAC_GET_STATUS_OTHER_RULE,
}

// pf.conf(5) documents macro names as starting with a letter, followed by
// letters, digits and underscores. The lexer is looser than the manual, but
// validating against the documented contract keeps a config that passes
// startup from failing at activation time.
var validMacroKeyRegex = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]*$`)

// Conservative name set for extensions[].name: alphanumeric first, then
// alphanumeric, dot, underscore or hyphen. Names come from the config file and
// are used verbatim in log lines and error messages, so path separators,
// whitespace and "../" shapes stay out.
var extensionsNameRegex = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

// pfctl(8) -F modifiers. FreeBSD documents nat, queue, ethernet, rules, states,
// Sources, info, Tables, osfp, Reset and all; OpenBSD drops nat, queue and
// ethernet. Sources and Reset are left out on purpose: they are not scoped to
// the -a anchor this app always passes, so they would flush global state.
// pfctl accepts abbreviations, this list does not - config stays explicit.
var pfctlFlushTargets = []string{"nat", "queue", "ethernet", "rules", "states", "info", "Tables", "osfp", "all"}

func New() *ConfigFile {
	configFile := ConfigFile{}
	return &configFile
}

func (c *ConfigFile) LoadConfig(configFile string) error {
	info, err := os.Stat(configFile)
	if err != nil {
		return fmt.Errorf("cannot access config file: %v", err)
	}

	perms := info.Mode().Perm()
	if perms&0037 != 0 {
		return fmt.Errorf("config file has insecure permissions: %o (should be 0640)", perms)
	}

	yamlFile, err := os.ReadFile(configFile)
	if err != nil {
		return fmt.Errorf("cannot read config file: %v", err)
	}

	err = yaml.Unmarshal(yamlFile, c)
	if err != nil {
		return fmt.Errorf("cannot parse config file: %v", err)
	}

	// Validate Config
	if err := c.validateRequiredSections(); err != nil {
		return err
	}

	return nil
}

// ValidateTokenTimeoutValue converts a token timeout such as "8", "30m", "1h"
// or "2d" into a duration. A value without a unit is read as hours, so "8"
// equals "8h". The result must be longer than zero and at most 30 days.
func ValidateTokenTimeoutValue(timeout string) (time.Duration, error) {
	matches := tokenTimeoutPattern.FindStringSubmatch(strings.TrimSpace(timeout))
	if matches == nil {
		return 0, fmt.Errorf("invalid token timeout %q (expected format: 8, 30m, 1h or 2d)", timeout)
	}

	value, err := strconv.Atoi(matches[1])
	if err != nil {
		return 0, fmt.Errorf("invalid token timeout %q: number out of range", timeout)
	}

	duration := time.Duration(value) * time.Hour
	switch matches[2] {
	case "m":
		duration = time.Duration(value) * time.Minute
	case "d":
		duration = time.Duration(value) * 24 * time.Hour
	}

	if duration == 0 {
		return 0, fmt.Errorf("invalid token timeout %q: must be longer than zero", timeout)
	}

	if duration > maxTokenTimeout {
		return 0, fmt.Errorf("token timeout %q exceeds maximum allowed duration of 30 days", timeout)
	}

	return duration, nil
}

// ValidateSchedulerInterval converts authpf.schedulerInterval into a duration.
// A bare number is read as seconds, the format the docs and the config sample
// use; anything else must be a Go duration such as "90s" or "2m". An empty
// value selects the default. Values below one second are rejected: a
// non-positive interval makes time.NewTicker panic in the scheduler goroutine,
// and a fractional one truncated to zero seconds does the same. Values above
// 30 days are rejected, see maxSchedulerInterval.
func ValidateSchedulerInterval(value string) (time.Duration, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return DefaultSchedulerInterval, nil
	}
	if schedulerSecondsPattern.MatchString(trimmed) {
		trimmed += "s"
	}

	duration, err := time.ParseDuration(trimmed)
	if err != nil {
		return 0, fmt.Errorf("invalid authpf.schedulerInterval %q (expected seconds like 60, or a duration like 90s)", value)
	}
	if duration < minSchedulerInterval {
		return 0, fmt.Errorf("authpf.schedulerInterval %q is below the minimum of 1s", value)
	}
	if duration > maxSchedulerInterval {
		return 0, fmt.Errorf("authpf.schedulerInterval %q exceeds the maximum of 30 days", value)
	}

	return duration, nil
}

// validateRequiredSections checks if all required configuration sections are defined
func (c *ConfigFile) validateRequiredSections() error {
	var missingFields []string

	// Check defaults section
	if c.Defaults.PfctlBinary == "" {
		missingFields = append(missingFields, "defaults.pfctlBinary")
	}

	// Check server section
	if c.Server.Bind == "" {
		missingFields = append(missingFields, "server.bind")
	}
	if c.Server.Port == 0 {
		missingFields = append(missingFields, "server.port")
	}
	if c.Server.Logfile == "" {
		missingFields = append(missingFields, "server.logfile")
	}
	if c.Server.ElevatorMode == "" {
		missingFields = append(missingFields, "server.elevatorMode")
	}

	if c.Server.JwtSecret != "" {
		if strings.TrimSpace(c.Server.JwtSecret) == "" {
			return fmt.Errorf("server.jwtSecret is set but contains only whitespace")
		}
		if len(c.Server.JwtSecret) < minJwtSecretLength {
			return fmt.Errorf("server.jwtSecret must be at least %d characters, got %d", minJwtSecretLength, len(c.Server.JwtSecret))
		}
	}

	// Check authpf section
	if c.AuthPF.Timeout == "" {
		missingFields = append(missingFields, "authpf.timeout")
	}
	if c.AuthPF.UserRulesRootFolder == "" {
		missingFields = append(missingFields, "authpf.userRulesRootFolder")
	}
	if c.AuthPF.UserRulesFile == "" {
		missingFields = append(missingFields, "authpf.userRulesFile")
	}
	if c.AuthPF.AnchorName == "" {
		missingFields = append(missingFields, "authpf.anchorName")
	}
	if len(c.AuthPF.FlushFilter) == 0 {
		missingFields = append(missingFields, "authpf.flushFilter")
	}

	if len(missingFields) > 0 {
		return fmt.Errorf("missing required configuration fields:\n  - %s", strings.Join(missingFields, "\n  - "))
	}

	return nil
}

// Validate checks every value in a parsed config file. It reports the first
// problem it finds and never logs, warns or exits: what an invalid config
// means is up to the caller. authpf-api refuses to start, other programs that
// read a config file (extension tooling, a config checker) may just print it.
func (c *ConfigFile) Validate() (err error) {
	if c.Server.JwtTokenTimeout != "" {
		if _, err = ValidateTokenTimeoutValue(c.Server.JwtTokenTimeout); err != nil {
			return fmt.Errorf("invalid server.jwtTokenTimeout: %w", err)
		}
	}

	if len(c.AuthPF.PfTable) > 0 {
		if err = validateAlphanumericASCII("authpf.pfTable", c.AuthPF.PfTable); err != nil {
			return err
		}
	}

	// Must be rejected here: an unusable value would panic in time.NewTicker
	// inside the scheduler goroutine and take the process down after startup.
	if _, err = ValidateSchedulerInterval(c.AuthPF.SchedulerInterval); err != nil {
		return err
	}

	// Validate all macro fields from config file
	for k, v := range c.Rbac.Users {
		// UserIP Check
		if err = validateIPAddr(v.UserIP); err != nil {
			return err
		}
		// Macros
		for mkey, mvalue := range v.Macros {
			if err = validateLength(mkey, 1, 128); err != nil {
				return err
			}
			if err = validateLength(mvalue, 1, 128); err != nil {
				return err
			}
			if err = validateAlphanumericASCII(mkey, mvalue); err != nil {
				return err
			}
			if err = validateMacroKey(mkey); err != nil {
				nerr := fmt.Errorf("invalid macro for user %s in configuration, %s", k, err)
				return nerr
			}
		}
		if len(v.PfTable) > 0 {
			if err = validateAlphanumericASCII(fmt.Sprintf("rbac.users.%s.pfTable", k), v.PfTable); err != nil {
				return err
			}
		}
	}

	if err = c.validatePfctlAndLifecycle(); err != nil {
		return err
	}
	if err = c.validatePathsAndTLS(); err != nil {
		return err
	}
	if err = c.validateRBAC(); err != nil {
		return err
	}
	if err = c.validateExtensions(); err != nil {
		return err
	}
	return nil
}

// ValidateTimeout checks a timeout duration as used by authpf.timeout and by
// the API's timeout request parameter. Shared on purpose: both must accept
// exactly the same strings, or a request that the API accepts would not be a
// timeout the config file could have carried.
func ValidateTimeout(timeoutStr string) error {
	if timeoutStr == "" {
		return fmt.Errorf("missing timeout validation parameter, timeout must be a valid duration (e.g., '1h', '30m'), got empty timeout string")
	}

	d, err := time.ParseDuration(timeoutStr)
	if err != nil {
		return fmt.Errorf("invalid timeout format, timeout must be a valid duration (e.g., '1h', '30m'), got: %s", timeoutStr)
	}

	if d < time.Second {
		return fmt.Errorf("timeout must be at least 1 second, provided timeout: %v", d)
	}

	if d > 24*time.Hour {
		return fmt.Errorf("timeout cannot exceed 24 hours, provided timeout: %v", d)
	}
	return nil
}

// Validate min/max length
func validateLength(value string, minLen int, maxLen int) error {
	if len(value) < minLen {
		return fmt.Errorf("input value %s below minimum length of %d characters", value, minLen)
	}
	if utf8.RuneCountInString(value) > maxLen {
		return fmt.Errorf("input value %s exceeds maximum length of %d characters", value, maxLen)
	}
	return nil
}

// Validate Value against allowed chars
func validateAlphanumericASCII(key, value string) error {
	var validStringRegex = regexp.MustCompile(`^[A-Za-z0-9_.]*$`)

	if len(value) == 0 {
		return fmt.Errorf("input must not be empty, key: %s", key)
	}
	if !validStringRegex.MatchString(value) {
		return fmt.Errorf("invalid characters found in config parameter: %s, only [a-zA-Z0-9_.] allowed, got: '%s'", key, value)
	}
	return nil
}

// Simple validation to have valid ip address (CIDR format not supported yet)
func validateIPAddr(value string) error {
	if len(value) > 0 {
		addr := strings.TrimSpace(value)
		if addr == "" {
			return fmt.Errorf("empty userIP address found in config file")
		}
		if net.ParseIP(addr) == nil {
			return fmt.Errorf("invalid userIP address found in config file: %s", addr)
		}
	}
	return nil
}

// validateMacroKey checks the macro name itself. Only the value was ever
// checked: validateAlphanumericASCII takes (key, value) and regex-tests the
// value, using the key solely to label the error.
//
// A key that is not a valid pf macro name still reaches pfctl as part of the
// -D argument, and produces a macro that no rules file can reference. Worse,
// it changes the shape of the argument the sudoers or doas allowlist matches
// against, so the config validates at startup and the activation fails later.
//
// user_ip and user_id are rejected outright. The app always passes both
// itself, before the user macros, and pfctl keeps the first definition of a
// command-line macro, so a user macro with either name is silently discarded.
func validateMacroKey(value string) error {
	if !validMacroKeyRegex.MatchString(value) {
		return fmt.Errorf("invalid macro key %q, only [A-Za-z][A-Za-z0-9_]* allowed", value)
	}
	if value == "user_ip" || value == "user_id" {
		return fmt.Errorf("macro key %q collides with the built-in pfctl macro of the same name", value)
	}
	return nil
}

// validateExtensions checks the extensions list itself: extensions[].name must
// be set, well-formed and must not appear twice. It runs before the server hands names to
// extension.Create, so an unknown name is still reported there, not here.
//
// A duplicated entry has to be rejected: loadExtensions would call Create()
// and Init() once per list entry, giving the same extension two instances and
// two sets of side effects (two fsnotify watchers on one file for file-rbac,
// two middleware instances for ratelimit).
//
// extensions[].config is deliberately not inspected: the shipped extensions
// live in their own repository and validate their own keys, this repo has no
// schema for them.
func (c *ConfigFile) validateExtensions() error {
	var (
		unnamed   bool
		invalid   []string
		nameCount = make(map[string]int, len(c.Extensions))
	)

	// Slice iteration, but every message below is built from sorted or
	// aggregated data, so it does not depend on the config order.
	for _, ext := range c.Extensions {
		switch {
		case ext.Name == "":
			unnamed = true
		case !extensionsNameRegex.MatchString(ext.Name):
			invalid = append(invalid, ext.Name)
		default:
			nameCount[ext.Name]++
		}
	}

	if unnamed {
		return errors.New("extensions: extension entry without name")
	}
	if len(invalid) > 0 {
		sort.Strings(invalid)
		return fmt.Errorf("invalid extensions[].name: %s (only %s allowed)",
			extensionsQuoteList(invalid), extensionsNameRegex.String())
	}

	var duplicates []string
	for name, count := range nameCount {
		if count > 1 {
			duplicates = append(duplicates, fmt.Sprintf("%q configured %d times", name, count))
		}
	}
	if len(duplicates) > 0 {
		sort.Strings(duplicates)
		return fmt.Errorf("duplicate extensions[].name: %s (each extension may be listed only once)",
			strings.Join(duplicates, ", "))
	}

	return nil
}

// extensionsQuoteList renders names as a comma-separated, quoted list.
func extensionsQuoteList(names []string) string {
	quoted := make([]string, len(names))
	for i, name := range names {
		quoted[i] = fmt.Sprintf("%q", name)
	}
	return strings.Join(quoted, ", ")
}

// validatePathsAndTLS checks the filesystem and listener parameters:
// authpf.anchorName, authpf.userRulesRootFolder, authpf.userRulesFile,
// server.bind, server.ssl.certificate, server.ssl.key and server.logfile.
//
// The SSL pair is checked here as a unit, by ValidateSSLFiles() below.
// Bootstrap() calls that function once more on its own: redundant, but it keeps
// the listener setup safe for any entry point that does not run Validate().
//
// An empty value is skipped whenever validateRequiredSections() already
// rejects the key as missing, so partial configurations keep working.
func (c *ConfigFile) validatePathsAndTLS() error {
	// The anchor name is interpolated into `pfctl -a <anchorName>/<user>(<id>)`
	// without escaping, so a character outside the pf word charset can reshape
	// the argument list and the anchor path itself.
	if len(c.AuthPF.AnchorName) > 0 {
		if err := validateAlphanumericASCII("authpf.anchorName", c.AuthPF.AnchorName); err != nil {
			return err
		}
	}

	if len(c.AuthPF.UserRulesRootFolder) > 0 {
		if err := pathsValidateUserRulesRoot(c.AuthPF.UserRulesRootFolder); err != nil {
			return err
		}
	}

	if len(c.AuthPF.UserRulesFile) > 0 {
		if err := pathsValidateUserRulesFile(c.AuthPF.UserRulesFile); err != nil {
			return err
		}
	}

	if len(c.Server.Bind) > 0 {
		if err := pathsValidateBind(c.Server.Bind); err != nil {
			return err
		}
	}

	if len(c.Server.Logfile) > 0 {
		if err := pathsValidateLogfile(c.Server.Logfile); err != nil {
			return err
		}
	}

	// Empty certificate and empty key mean "no TLS" and are accepted; anything
	// else has to be a complete, parseable and matching pair.
	if err := ValidateSSLFiles(c.Server.SSL.Certificate, c.Server.SSL.Key); err != nil {
		return err
	}

	return nil
}

// pathsValidateUserRulesRoot checks the folder every user's rules file is read
// from. Without this check a wrong path is only reported per-user at
// activation time, so the server starts and then fails every request.
//
// The folder is never created here: ownership and permissions of the rules
// tree belong to the operator, not to the API process.
func pathsValidateUserRulesRoot(path string) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("authpf.userRulesRootFolder must be an absolute path, got: %s", path)
	}

	fi, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("authpf.userRulesRootFolder does not exist: %s", path)
		}
		return fmt.Errorf("cannot access authpf.userRulesRootFolder: %s - %v", path, err)
	}
	if !fi.IsDir() {
		return fmt.Errorf("authpf.userRulesRootFolder is not a directory: %s", path)
	}

	// Stat cannot see a missing read permission or an unreadable directory on a
	// network mount, so read one entry the way the import does. Readdirnames
	// returns io.EOF for an empty directory, which is not an error here.
	dir, err := os.Open(path)
	if err == nil {
		_, err = dir.Readdirnames(1)
		_ = dir.Close()
	}
	if err != nil && err != io.EOF {
		return fmt.Errorf("authpf.userRulesRootFolder is not readable: %s - %v", path, err)
	}

	return nil
}

// pathsValidateUserRulesFile checks the single file name that is joined to
// userRulesRootFolder/<username> for every activation. A name with a path
// separator in it is a misconfiguration rather than an attack: exec catches
// traversal at activation time, which is far too late to be actionable.
func pathsValidateUserRulesFile(name string) error {
	if strings.ContainsAny(name, `/\`) || strings.Contains(name, "..") || strings.HasPrefix(name, ".") {
		return fmt.Errorf(
			"authpf.userRulesFile must be a plain file name, without a path separator, '..' or a leading dot, got: %s",
			name,
		)
	}

	// Dots are allowed on purpose: the shipped default is authpf.rules.
	return validateAlphanumericASCII("authpf.userRulesFile", name)
}

// pathsValidateBind checks the listen address. server.go builds the address as
// "<bind>:<port>", so only a bare address is usable: hostnames would turn
// startup into a DNS lookup that can silently pick another interface, and
// "host:port" or CIDR shapes are never accepted by net.Listen for this field.
func pathsValidateBind(bind string) error {
	// localhost is the one name that is allowed: it is resolved by the system
	// resolver to loopback and is the documented way to bind locally only.
	if strings.EqualFold(bind, "localhost") {
		return nil
	}

	// An IPv6 literal has to keep its brackets, otherwise "<bind>:<port>" has
	// too many colons and net.Listen rejects it.
	host := bind
	if strings.HasPrefix(bind, "[") {
		if !strings.HasSuffix(bind, "]") {
			return fmt.Errorf("server.bind has an unmatched '[', got: %q", bind)
		}
		host = bind[1 : len(bind)-1]
	}

	if net.ParseIP(host) == nil {
		return fmt.Errorf("server.bind must be an IPv4/IPv6 address or localhost, got: %q", bind)
	}

	return nil
}

// OpenLogfile opens server.logfile the way the logger needs it. It is the only
// place these flags and this mode appear, so the startup check and the writer
// cannot drift apart.
//
// Relative paths stay allowed, they are resolved against the working directory
// the process was started in.
func OpenLogfile(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0640)
}

// pathsValidateLogfile opens the logfile exactly like the logger will and
// closes it again. In -foreground mode the path is never opened at runtime, so
// a typo or an unwritable directory used to be accepted silently.
func pathsValidateLogfile(path string) error {
	f, err := OpenLogfile(path)
	if err != nil {
		return fmt.Errorf("cannot open server.logfile: %s - %v", path, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("cannot close server.logfile: %s - %v", path, err)
	}
	return nil
}

// validatePfctlAndLifecycle checks the parameters that decide how authpf-api
// talks to pf and what it does at startup and shutdown:
// defaults.pfctlBinary, server.elevatorMode, authpf.onStartup,
// authpf.onShutdown, authpf.timeout and authpf.flushFilter.
func (c *ConfigFile) validatePfctlAndLifecycle() error {

	if path := c.Defaults.PfctlBinary; path != "" {
		resolved := path
		if !filepath.IsAbs(resolved) {
			// LookPath searches PATH for a bare name and tries a name containing
			// a separator directly - that keeps "echo" and "./pfctl" both valid.
			found, err := exec.LookPath(resolved)
			if err != nil {
				return fmt.Errorf("defaults.pfctlBinary %q is not found in PATH: %w", path, err)
			}
			resolved = found
		}
		info, err := os.Stat(resolved)
		if err != nil {
			return fmt.Errorf("defaults.pfctlBinary %q cannot be accessed: %w", path, err)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("defaults.pfctlBinary %q must be a regular file", path)
		}
		if info.Mode().Perm()&0111 == 0 {
			return fmt.Errorf("defaults.pfctlBinary %q is not executable", path)
		}
	}

	if c.Server.ElevatorMode != "" {
		switch c.Server.ElevatorMode {
		case "none":
		case "sudo", "doas":
			if _, err := exec.LookPath(c.Server.ElevatorMode); err != nil {
				return fmt.Errorf("server.elevatorMode %q program is not found in PATH: %w", c.Server.ElevatorMode, err)
			}
		default:
			return fmt.Errorf("invalid server.elevatorMode %q: allowed values are none, sudo, doas", c.Server.ElevatorMode)
		}
	}

	if v := c.AuthPF.OnStartup; v != "" {
		switch v {
		case "none", "import", "importflush":
		default:
			return fmt.Errorf("invalid authpf.onStartup %q: allowed values are none, import, importflush", v)
		}
	}

	if v := c.AuthPF.OnShutdown; v != "" {
		switch v {
		case "none", "flushall":
		default:
			return fmt.Errorf("invalid authpf.onShutdown %q: allowed values are none, flushall", v)
		}
	}

	if c.AuthPF.Timeout != "" {
		if err := ValidateTimeout(c.AuthPF.Timeout); err != nil {
			return fmt.Errorf("invalid authpf.timeout: %w", err)
		}
	}

	for _, target := range c.AuthPF.FlushFilter {
		for _, r := range target {
			if unicode.IsSpace(r) || unicode.IsControl(r) || r == '/' || r == '\\' {
				return fmt.Errorf("invalid authpf.flushFilter target %q: whitespace, control characters and path separators are not allowed", target)
			}
		}
		if strings.HasPrefix(target, "-") {
			return fmt.Errorf("invalid authpf.flushFilter target %q: leading '-' is not allowed", target)
		}
		if !slices.Contains(pfctlFlushTargets, target) {
			return fmt.Errorf("invalid authpf.flushFilter target %q: allowed values are %s", target, strings.Join(pfctlFlushTargets, ", "))
		}
	}

	return nil
}

// validateRBAC checks the rbac section at startup: roles, users and their credentials.
func (c *ConfigFile) validateRBAC() error {
	if len(c.Rbac.Users) == 0 {
		return fmt.Errorf("rbac.users: no users configured")
	}

	roleNames := make([]string, 0, len(c.Rbac.Roles))
	for name := range c.Rbac.Roles {
		roleNames = append(roleNames, name)
	}
	sort.Strings(roleNames)
	for _, role := range roleNames {
		for _, permission := range c.Rbac.Roles[role].Permissions {
			if !slices.Contains(rbacPermissions, permission) {
				return fmt.Errorf("rbac.roles.%s.permissions: unknown permission %q; allowed values: %s", role, permission, strings.Join(rbacPermissions, ", "))
			}
		}
	}

	userNames := make([]string, 0, len(c.Rbac.Users))
	for name := range c.Rbac.Users {
		userNames = append(userNames, name)
	}
	sort.Strings(userNames)
	seenIDs := make(map[int]string)
	for _, username := range userNames {
		user := c.Rbac.Users[username]
		if len(username) > 255 || !rbacUsernameRegex.MatchString(username) {
			return fmt.Errorf("rbac.users: invalid username %q: must match [a-zA-Z0-9_-]+ and be at most 255 characters", username)
		}
		if user.Password == "" {
			return fmt.Errorf("rbac.users.%s.password: must not be empty", username)
		}
		// Cost parses bcrypt's version and cost; the strict shape check also
		// ensures its encoded salt/hash are complete and contain only bcrypt characters.
		if !rbacBcryptHashRegex.MatchString(user.Password) {
			return fmt.Errorf("rbac.users.%s.password: invalid bcrypt hash format", username)
		}
		if _, err := rbacBcryptEncoding.DecodeString(user.Password[7:29]); err != nil {
			return fmt.Errorf("rbac.users.%s.password: invalid bcrypt hash format", username)
		}
		if _, err := rbacBcryptEncoding.DecodeString(user.Password[29:]); err != nil {
			return fmt.Errorf("rbac.users.%s.password: invalid bcrypt hash format", username)
		}
		if _, err := bcrypt.Cost([]byte(user.Password)); err != nil {
			return fmt.Errorf("rbac.users.%s.password: invalid bcrypt hash: %v", username, err)
		}
		if user.Role == "" {
			return fmt.Errorf("rbac.users.%s.role: must not be empty", username)
		}
		if _, ok := c.Rbac.Roles[user.Role]; !ok {
			return fmt.Errorf("rbac.users.%s.role: unknown role %q", username, user.Role)
		}
		if user.UserID < 0 {
			return fmt.Errorf("rbac.users.%s.userId: must not be negative", username)
		}
		if user.UserID > 0 {
			if previous, ok := seenIDs[user.UserID]; ok {
				return fmt.Errorf("rbac.users.%s.userId: duplicate userId %d also configured for user %q", username, user.UserID, previous)
			}
			seenIDs[user.UserID] = username
		}
	}
	return nil
}

// ValidateSSLFiles checks if SSL certificate and key files exist and are
// readable, and that the key belongs to the certificate.
func ValidateSSLFiles(certPath, keyPath string) error {
	if certPath == "" {
		// A key without a certificate is a misconfiguration, not "SSL disabled":
		// SSL stays off and the key is silently ignored.
		if keyPath != "" {
			return fmt.Errorf("server.ssl.key is configured but server.ssl.certificate is empty, SSL would stay disabled: %s", keyPath)
		}
		return nil
	}
	if keyPath == "" {
		return fmt.Errorf("server.ssl.certificate is configured but server.ssl.key is empty: %s", certPath)
	}

	if _, err := os.Stat(certPath); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("SSL certificate file not found: %s", certPath)
		}
		return fmt.Errorf("cannot access SSL certificate file: %s - %v", certPath, err)
	}
	if _, err := os.Stat(keyPath); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("SSL key file not found: %s", keyPath)
		}
		return fmt.Errorf("cannot access SSL key file: %s - %v", keyPath, err)
	}

	// Parsing both files proves the private key belongs to the certificate.
	// Neither was ever checked before, so a mismatch or a corrupt file only
	// surfaced in the first TLS handshake.
	if _, err := loadSSLKeyPair(certPath, keyPath); err != nil {
		return err
	}
	return nil
}

// loadSSLKeyPair is the only place that touches the SSL files on disk. The
// server hands the result to Echo instead of a path, because Echo resolves
// StartTLS path arguments through fs.FS (default os.DirFS(".")), which rejects
// absolute paths with EINVAL.
func loadSSLKeyPair(certPath, keyPath string) (tls.Certificate, error) {
	tlsCert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("invalid SSL certificate/key pair, certificate: %s, key: %s - %w", certPath, keyPath, err)
	}
	return tlsCert, nil
}

// TLSKeyPair returns the configured certificate/key pair, already checked by
// Validate(). The zero certificate means "SSL disabled" (no certificate
// configured) and is not an error.
func (ssl *ConfigFileServerSSL) TLSKeyPair() (tls.Certificate, error) {
	if ssl.Certificate == "" {
		return tls.Certificate{}, nil
	}
	return loadSSLKeyPair(ssl.Certificate, ssl.Key)
}
