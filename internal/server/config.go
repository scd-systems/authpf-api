package server

import (
	"fmt"
	"net"
	"regexp"
	"strings"
	"unicode/utf8"
)

// Validate ConfigFile Values
func (s *Server) validateConfig() (err error) {
	if len(s.config.AuthPF.PfTable) > 0 {
		if err = validateAlphanumericASCII("authpf.pfTable", s.config.AuthPF.PfTable); err != nil {
			return err
		}
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

// pf.conf(5) documents macro names as starting with a letter, followed by
// letters, digits and underscores. The lexer is looser than the manual, but
// validating against the documented contract keeps a config that passes
// startup from failing at activation time.
var validMacroKeyRegex = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]*$`)

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
