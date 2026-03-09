package server

import (
	"fmt"
	"net"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/scd-systems/authpf-api/pkg/config"
)

// Validate ConfigFile Values
func (s *Server) validateConfig() (err error) {
	// Validate all macro fields from config file
	for k := range s.config.Rbac.Users {
		if err = validateIPAddr(s.config.Rbac.Users[k].UserIP); err != nil {
			return err
		}
		for mkey, mvalue := range s.config.Rbac.Users[k].Macros {
			if err = validateLength(mkey, 1, 128); err != nil {
				return err
			}
			if err = validateLength(mvalue, 1, 128); err != nil {
				return err
			}
			if err = validateAlphanumericASCII(mvalue); err != nil {
				return err
			}
			if err = validateMacroKey(s.config.Rbac.Users[k], mkey); err != nil {
				nerr := fmt.Errorf("same twice parameters found for user %s in configuration, %s", k, err)
				return nerr
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
func validateAlphanumericASCII(value string) error {
	var validStringRegex = regexp.MustCompile(`^[A-Za-z0-9_.]*$`)

	if len(value) == 0 {
		return fmt.Errorf("input must not be empty")
	}
	if !validStringRegex.MatchString(value) {
		return fmt.Errorf("invalid characters found in macro, only [a-zA-Z0-9_.] allowed, got: %s", value)
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
		if net.ParseIP(value) == nil {
			return fmt.Errorf("invalid userIP address found in config file: %s", value)
		}
	}
	return nil
}

func validateMacroKey(user config.ConfigFileRbacUsers, value string) error {
	if len(value) > 0 {
		if chk := strings.Compare(value, "user_ip"); chk == 0 && len(user.UserIP) > 0 {
			return fmt.Errorf("userIp and macro user_ip defined (same)")
		}
		if chk := strings.Compare(value, "user_id"); chk == 0 && user.UserID > 0 {
			return fmt.Errorf("userId and macro user_id defined (same)")
		}
	}
	return nil
}
