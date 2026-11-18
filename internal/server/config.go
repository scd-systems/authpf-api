package server

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	stdexec "os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	pfexec "github.com/scd-systems/authpf-api/internal/exec"
	"github.com/scd-systems/authpf-api/pkg/config"
	"golang.org/x/crypto/bcrypt"
)

// The API applies the same username contract to requests in internal/api/checks.go.
var rbacUsernameRegex = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)
var rbacBcryptHashRegex = regexp.MustCompile(`^\$2[aby]\$[0-9]{2}\$[./A-Za-z0-9]{53}$`)
var rbacBcryptEncoding = base64.NewEncoding("./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789").WithPadding(base64.NoPadding)

var rbacPermissions = []string{
	config.RBAC_ACTIVATE_OWN_RULE,
	config.RBAC_ACTIVATE_OTHER_RULE,
	config.RBAC_DEACTIVATE_OWN_RULE,
	config.RBAC_DEACTIVATE_OTHER_RULE,
	config.RBAC_GET_STATUS_OWN_RULE,
	config.RBAC_GET_STATUS_OTHER_RULE,
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

// Validate ConfigFile Values
func (s *Server) validateConfig() (err error) {
	// An empty value is valid: auth.Login falls back to its own 8h default.
	if s.config.Server.JwtTokenTimeout != "" {
		if _, err = config.ValidateTokenTimeoutValue(s.config.Server.JwtTokenTimeout); err != nil {
			return fmt.Errorf("invalid server.jwtTokenTimeout: %w", err)
		}
	}

	if len(s.config.AuthPF.PfTable) > 0 {
		if err = validateAlphanumericASCII("authpf.pfTable", s.config.AuthPF.PfTable); err != nil {
			return err
		}
	}

	// Must be rejected here: an unusable value would panic in time.NewTicker
	// inside the scheduler goroutine and take the process down after startup.
	interval, err := config.ValidateSchedulerInterval(s.config.AuthPF.SchedulerInterval)
	if err != nil {
		return err
	}
	if interval > config.SchedulerIntervalWarnThreshold {
		s.logger.Warn().Msgf("⚠️ authpf.schedulerInterval is %s: expired anchors are only removed on the next loop, so they stay active up to %s past their own timeout", interval, interval)
	}

	// Validate all macro fields from config file
	for k, v := range s.config.Rbac.Users {
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

	// The four groups below live in their own config_*.go files, one per
	// work package, so they can be developed and reviewed independently.
	if err = s.validatePfctlAndLifecycle(); err != nil {
		return err
	}
	if err = s.validatePathsAndTLS(); err != nil {
		return err
	}
	if err = s.validateRBAC(); err != nil {
		return err
	}
	if err = s.validateExtensions(); err != nil {
		return err
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
// be set, well-formed and must not appear twice. It runs at startup before
// loadExtensions, so an unknown name is still reported there, not here.
//
// A duplicated entry has to be rejected: loadExtensions would call Create()
// and Init() once per list entry, giving the same extension two instances and
// two sets of side effects (two fsnotify watchers on one file for file-rbac,
// two middleware instances for ratelimit).
//
// extensions[].config is deliberately not inspected: the shipped extensions
// live in their own repository and validate their own keys, this repo has no
// schema for them.
func (s *Server) validateExtensions() error {
	var (
		unnamed   bool
		invalid   []string
		nameCount = make(map[string]int, len(s.config.Extensions))
	)

	// Slice iteration, but every message below is built from sorted or
	// aggregated data, so it does not depend on the config order.
	for _, ext := range s.config.Extensions {
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
// The SSL pair is validated by validateSSLFiles() in bootstrap.go, which
// Bootstrap() calls right after validateConfig().
//
// An empty value is skipped whenever validateRequiredSections() already
// rejects the key as missing, so partial configurations keep working.
func (s *Server) validatePathsAndTLS() error {
	// The anchor name is interpolated into `pfctl -a <anchorName>/<user>(<id>)`
	// without escaping, so a character outside the pf word charset can reshape
	// the argument list and the anchor path itself.
	if len(s.config.AuthPF.AnchorName) > 0 {
		if err := validateAlphanumericASCII("authpf.anchorName", s.config.AuthPF.AnchorName); err != nil {
			return err
		}
	}

	if len(s.config.AuthPF.UserRulesRootFolder) > 0 {
		if err := pathsValidateUserRulesRoot(s.config.AuthPF.UserRulesRootFolder); err != nil {
			return err
		}
	}

	if len(s.config.AuthPF.UserRulesFile) > 0 {
		if err := pathsValidateUserRulesFile(s.config.AuthPF.UserRulesFile); err != nil {
			return err
		}
	}

	if len(s.config.Server.Bind) > 0 {
		if err := pathsValidateBind(s.config.Server.Bind); err != nil {
			return err
		}
	}

	if len(s.config.Server.Logfile) > 0 {
		if err := pathsValidateLogfile(s.config.Server.Logfile); err != nil {
			return err
		}
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

// pathsValidateLogfile opens the logfile exactly like the logger will and
// closes it again. In -foreground mode the path is never opened at runtime, so
// a typo or an unwritable directory used to be accepted silently.
//
// Relative paths stay allowed, they are resolved against the working directory
// the process was started in.
func pathsValidateLogfile(path string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0640)
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
func (s *Server) validatePfctlAndLifecycle() error {
	c := s.config

	if path := c.Defaults.PfctlBinary; path != "" {
		resolved := path
		if !filepath.IsAbs(resolved) {
			// LookPath searches PATH for a bare name and tries a name containing
			// a separator directly - that keeps "echo" and "./pfctl" both valid.
			found, err := stdexec.LookPath(resolved)
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
			if _, err := stdexec.LookPath(c.Server.ElevatorMode); err != nil {
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
		if err := pfexec.ValidateTimeout(c.AuthPF.Timeout); err != nil {
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
func (s *Server) validateRBAC() error {
	if len(s.config.Rbac.Users) == 0 {
		return fmt.Errorf("rbac.users: no users configured")
	}

	roleNames := make([]string, 0, len(s.config.Rbac.Roles))
	for name := range s.config.Rbac.Roles {
		roleNames = append(roleNames, name)
	}
	sort.Strings(roleNames)
	for _, role := range roleNames {
		for _, permission := range s.config.Rbac.Roles[role].Permissions {
			if !slices.Contains(rbacPermissions, permission) {
				return fmt.Errorf("rbac.roles.%s.permissions: unknown permission %q; allowed values: %s", role, permission, strings.Join(rbacPermissions, ", "))
			}
		}
	}

	userNames := make([]string, 0, len(s.config.Rbac.Users))
	for name := range s.config.Rbac.Users {
		userNames = append(userNames, name)
	}
	sort.Strings(userNames)
	seenIDs := make(map[int]string)
	for _, username := range userNames {
		user := s.config.Rbac.Users[username]
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
		if _, ok := s.config.Rbac.Roles[user.Role]; !ok {
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
