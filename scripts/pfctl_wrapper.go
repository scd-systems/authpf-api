package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

const (
	pfctlBinary        = "/sbin/pfctl"
	authpfRulesRoot    = "/etc/authpf"
	authpfAnchorPrefix = "authpf"
	maxAnchorLength    = 256
	maxDefineLength    = 256
	maxFilterLength    = 64
	maxFilePathLength  = 4096
)

// validateAnchor validates anchor name format: authpf/username(uid)
func validateAnchor(anchor string) error {
	if len(anchor) > maxAnchorLength {
		return fmt.Errorf("anchor name too long: %d > %d", len(anchor), maxAnchorLength)
	}

	// Must start with authpf/
	if !strings.HasPrefix(anchor, authpfAnchorPrefix+"/") {
		return fmt.Errorf("invalid anchor prefix, must start with '%s/'", authpfAnchorPrefix)
	}

	// Parse format: authpf/username(uid)
	pattern := regexp.MustCompile(`^authpf/([a-zA-Z0-9._-]+)\((\d+)\)$`)
	matches := pattern.FindStringSubmatch(anchor)
	if len(matches) != 3 {
		return fmt.Errorf("invalid anchor format, expected 'authpf/username(uid)', got '%s'", anchor)
	}

	username := matches[1]
	uidStr := matches[2]

	// Validate username length
	if len(username) == 0 || len(username) > 32 {
		return fmt.Errorf("invalid username length: %d", len(username))
	}

	// Validate UID is numeric and reasonable
	uid, err := strconv.ParseInt(uidStr, 10, 32)
	if err != nil {
		return fmt.Errorf("invalid UID: %s", uidStr)
	}

	if uid < 0 || uid > 2147483647 {
		return fmt.Errorf("UID out of valid range: %d", uid)
	}

	return nil
}

// validateIP validates IPv4 or IPv6 address
func validateIP(ipStr string) error {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return fmt.Errorf("invalid IP address: %s", ipStr)
	}
	return nil
}

// validateDefine validates define parameter (user_ip=... or user_id=...)
func validateDefine(define string) error {
	if len(define) > maxDefineLength {
		return fmt.Errorf("define parameter too long: %d > %d", len(define), maxDefineLength)
	}

	parts := strings.SplitN(define, "=", 2)
	if len(parts) != 2 {
		return fmt.Errorf("invalid define format, expected 'key=value', got '%s'", define)
	}

	key := parts[0]
	value := parts[1]

	// Validate key format (alphanumeric and underscore only)
	if !regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`).MatchString(key) {
		return fmt.Errorf("invalid define key: %s", key)
	}

	switch key {
	case "user_ip":
		if err := validateIP(value); err != nil {
			return err
		}
	case "user_id":
		uid, err := strconv.ParseInt(value, 10, 32)
		if err != nil {
			return fmt.Errorf("invalid user_id value (must be numeric): %s", value)
		}
		if uid < 0 || uid > 2147483647 {
			return fmt.Errorf("user_id out of valid range: %d", uid)
		}
	default:
		return fmt.Errorf("unknown define key: %s", key)
	}

	return nil
}

// validateFilterType validates filter type (rules, nat, etc.)
func validateFilterType(filter string) error {
	if len(filter) > maxFilterLength {
		return fmt.Errorf("filter type too long: %d > %d", len(filter), maxFilterLength)
	}

	if !regexp.MustCompile(`^[a-zA-Z0-9]+$`).MatchString(filter) {
		return fmt.Errorf("invalid filter type: %s", filter)
	}

	// Whitelist known filter types
	validFilters := map[string]bool{
		"rules": true,
		"nat":   true,
		"rdr":   true,
		"all":   true,
	}

	if !validFilters[filter] {
		return fmt.Errorf("unsupported filter type: %s", filter)
	}

	return nil
}

// validateFilePath validates file path is within allowed directory
func validateFilePath(filePath string) error {
	if len(filePath) > maxFilePathLength {
		return fmt.Errorf("file path too long: %d > %d", len(filePath), maxFilePathLength)
	}

	// Check for path traversal attempts
	if strings.Contains(filePath, "..") {
		return fmt.Errorf("path traversal detected: %s", filePath)
	}

	// Must be absolute path
	if !strings.HasPrefix(filePath, "/") {
		return fmt.Errorf("file path must be absolute: %s", filePath)
	}

	// Must be within authpfRulesRoot
	absPath, err := filepath.Abs(filePath)
	if err != nil {
		return fmt.Errorf("invalid file path: %v", err)
	}

	absRoot, err := filepath.Abs(authpfRulesRoot)
	if err != nil {
		return fmt.Errorf("invalid rules root: %v", err)
	}

	if !strings.HasPrefix(absPath, absRoot) {
		return fmt.Errorf("file path outside allowed directory: %s", filePath)
	}

	// File must exist and be readable
	info, err := os.Stat(absPath)
	if err != nil {
		return fmt.Errorf("cannot access file: %v", err)
	}

	if !info.Mode().IsRegular() {
		return fmt.Errorf("not a regular file: %s", filePath)
	}

	return nil
}

// executePfctl executes pfctl with validated arguments
func executePfctl(args []string) error {
	// Verify pfctl binary exists and is executable
	if _, err := os.Stat(pfctlBinary); err != nil {
		return fmt.Errorf("pfctl binary not found: %s", pfctlBinary)
	}

	cmd := exec.Command(pfctlBinary, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	return cmd.Run()
}

func main() {
	// Define flags
	anchor := flag.String("a", "", "Anchor name (format: authpf/username(uid))")
	define := flag.String("D", "", "Define variable (user_ip=... or user_id=...)")
	filter := flag.String("F", "", "Flush filter (rules, nat, rdr, all)")
	filePath := flag.String("f", "", "Load rules from file")
	showAnchors := flag.Bool("sA", false, "Show all anchors (pfctl -sA)")

	flag.Parse()

	// Build arguments for pfctl
	var args []string

	// Validate and add anchor if provided
	if *anchor != "" {
		if err := validateAnchor(*anchor); err != nil {
			fmt.Fprintf(os.Stderr, "Error: invalid anchor: %v\n", err)
			os.Exit(1)
		}
		args = append(args, "-a", *anchor)
	}

	// Validate and add define if provided
	if *define != "" {
		if err := validateDefine(*define); err != nil {
			fmt.Fprintf(os.Stderr, "Error: invalid define: %v\n", err)
			os.Exit(1)
		}
		args = append(args, "-D", *define)
	}

	// Validate and add filter if provided
	if *filter != "" {
		if err := validateFilterType(*filter); err != nil {
			fmt.Fprintf(os.Stderr, "Error: invalid filter: %v\n", err)
			os.Exit(1)
		}
		args = append(args, "-F", *filter)
	}

	// Validate and add file path if provided
	if *filePath != "" {
		if err := validateFilePath(*filePath); err != nil {
			fmt.Fprintf(os.Stderr, "Error: invalid file path: %v\n", err)
			os.Exit(1)
		}
		args = append(args, "-f", *filePath)
	}

	// Add show anchors flag if provided
	if *showAnchors {
		args = append(args, "-sA")
	}

	// At least one argument must be provided
	if len(args) == 0 {
		fmt.Fprintf(os.Stderr, "Error: No arguments provided\n")
		fmt.Fprintf(os.Stderr, "Usage: %s [options]\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "\nOptions:\n")
		flag.PrintDefaults()
		os.Exit(1)
	}

	// Execute pfctl
	if err := executePfctl(args); err != nil {
		fmt.Fprintf(os.Stderr, "Error executing pfctl: %v\n", err)
		os.Exit(1)
	}
}
