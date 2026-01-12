# Authpf-API

A RESTful HTTP API for pf user rules.

## Overview

**Authpf-API** is a Go-based REST API that provides a secure interface for managing packet filter (pf) user rules on FreeBSD and OpenBSD systems. It allows users to activate and deactivate pf rules through HTTP endpoints with JWT token authentication and fine-grained permission control.
The original authpf is "_a user shell for authenticating gateways_" -- [openbsd.org](https://man.openbsd.org/authpf) and is based on SSH logins.
Authpf-API is an alternative by using HTTP/S to load/unload pf user rules.

## Features

- 🔐 **JWT Authentication** - Secure token-based authentication
- 👥 **Role-Based Access Control (RBAC)** - Fine-grained permission management
- ⏱️ **Automatic Expiration** - Rules automatically expire after configured timeout
- 🔄 **Scheduled Cleanup** - Periodic cleanup of expired rules
- 🏗️ **Cross-Platform Build** - Support for FreeBSD and OpenBSD on multiple architectures
- 🧑‍💼 **Runs as User** - API can run as user and use elevator tool (sudo/doas) to run pfctl subcommands

## Supported Platforms

### Operating Systems
- FreeBSD
- OpenBSD
- macOS
- Other pf based OS with anchor support

### Architectures
- amd64 (x86-64)
- arm64 (ARM 64-bit)

## Requirements

- Go 1.24 or higher
- pfctl binary (usually pre-installed on BSD systems)
- Optional: sudo or doas for privilege escalation

## Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/scd-systems/authpf-api.git
cd authpf-api

# Build for current system
make build

# Or build for all platforms
make build-all

# Run the application
./build/authpf-api-freebsd-amd64 -foreground
```

### Using Make

```bash
# Show available targets
make help

# Build for specific platform
make build GOOS=freebsd GOARCH=amd64

# Run tests
make test

# Generate coverage report
make coverage-html
```

## Configuration

The application is configured via a YAML configuration file. By default, it uses `/usr/local/etc/authpf-api-config.yaml`.

### Configuration File Example

```yaml
# Default configuration settings applied globally
defaults:
  # Maximum timeout for operations (e.g., 30m, 1h)
  timeout: 30m

  # Path to the pfctl binary executable
  pfctlBinary: /sbin/pfctl

# AuthPF-specific configuration
authpf:
  # Root directory where user-specific rule files are stored
  userRulesRootfolder: /etc/authpf/users

  # Filename for user rules within the userRulesRootfolder
  userRulesFile: authpf.rules

  # Name of the PF anchor to use for rule management
  anchorName: authpf

  # Allow login the same user from different IP's
  multiUserIP: false    

# Server configuration
server:
  # IP address to bind the server to (127.0.0.1 for localhost only)
  bind: 127.0.0.1

  # Port number for the HTTP/HTTPS server
  port: 8080

  # SSL/TLS configuration
  ssl:
    # Path to SSL certificate file (leave empty to disable SSL)
    certificate: 
    # Path to SSL private key file
    key: key.pem

  # JWT secret key for token signing - MUST be changed before production deployment
  jwtSecret: your-secret-key-change-in-production

  # Elevator mode for privilege escalation (none, sudo, or doas)
  # Required when running server as non-root user
  # sudo:   user	ALL = (root) NOPASSWD:/sbin/pfctl -a "authpf" -D "client_ip=*" -D "client_id=*" -f "/etc/authpf/users/*"
  # doas:   permit nopass as root cmd /sbin/pfctl -a "authpf" -D "client_ip=*" -D "client_id=*" -f "/etc/authpf/users/*"
  elevatorMode: none

  # Path to the server logfile
  logfile: /var/log/authpf-api.log

# Role-Based Access Control (RBAC) configuration
rbac:
  # Role definitions with associated permissions
  roles:
    # Administrator role with full permissions
    admin:
      permissions:
        - delete_other_rules  # Allow user to activate their own rules
        - delete_own_rules    # Allow user to activate rules from other users
        - view_other_rules    # Allow user to view the status of their own loaded rules
        - view_own_rules      # Allow user to view the status of loaded rules from all users
        - set_other_rules     # Allow user to unload/deactivate their own rules
        - set_own_rules       # Allow user to unload/deactivate rules from other users

    # Regular user role with limited permissions
    user:
      permissions:
        - delete_own_rules
        - view_own_rules
        - set_own_rules
  
  # User account definitions with credentials and role assignments
  users:
    # Name of the user
    username:
      # password hash (can be bcrypt2 or sha256) (example: echo -n "testing" | sha256)
      password: cf80cd8aed482d5d1527d7dc72fceff84e6326592848447d2dc0b0e87dfc9a90
      # Role assigned to this user
      role: admin
      # Numeric user ID (default 0 if not defined)
      userId: 1000
```

### Environment Variables

```bash
# Configuration file path
export CONFIG_FILE=/path/to/config.yaml

# Log level (debug, info, warn, error)
export LOG_LEVEL=info
```

### Command-Line Flags

```bash
# Show version and exit
./authpf-api -version

# Log to stdout instead of logfile
./authpf-api -foreground

# Generate User Password (bcrypted)
./authpf-api -gen-user-password
```

## API Endpoints

### Authentication

#### Login
```http
POST /login
Content-Type: application/json

{
  "username": "authpf-user1",
  "password": "testing"
}
```

**Response (200 OK):**
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

### AuthPF Rules

All endpoints require JWT authentication via `Authorization: Bearer <token>` header.

#### Activate Rule
```http
POST /api/v1/authpf/activate?timeout=30m
Authorization: Bearer <token>
Content-Type: application/json
```

**Response (201 Created):**
```json
{
  "status": "activated",
  "user": "authpf-user1",
  "msg": "authpf rule is being loaded"
}
```

#### Deactivate Rule
```http
DELETE /api/v1/authpf/activate
Authorization: Bearer <token>
Content-Type: application/json

{}
```

**Response (202 Accepted):**
```json
{
  "status": "queued",
  "user": "authpf-user1",
  "msg": "authpf rule is being unloaded"
}
```

#### Get All Rules
```http
GET /api/v1/authpf/all
Authorization: Bearer <token>
```

**Response (200 OK):**
```json
{
  "authpf-user1": {
    "username": "authpf-user1",
    "timeout": "30m",
    "client_ip": "192.168.1.100",
    "expireat": "2026-01-07T22:00:00Z"
  }
}
```

#### Delete All Rules (Admin Only)
```http
DELETE /api/v1/authpf/all
Authorization: Bearer <token>
```

**Response (200 OK):**
```json
{
  "status": "cleared"
}
```

### Query Parameters:

| Parameter | Description |
|-----------|-------------|
| `authpf_username` | Activate/Deactivate the authpf rules from another user (require set_other_rules/delete_other_rules permissions in role) |
| `timeout` | Modify the authpf expire timeout (default 30m) |

Example:

```http
POST /api/v1/authpf/activate?authpf_username=othername
Authorization: Bearer <token>
```

## Permissions

### Available Permissions

| Permission | Description |
|-----------|-------------|
| `set_own_rules` | Allow user to activate authpf rules |
| `set_other_rules` | Allow user to activate rules from other users |
| `delete_own_rules` | Allow user to deactivate their own rules |
| `delete_other_rules` | Allow user to deactivate rules from other users |
| `view_own_rules` | Allow user to view their own rules |
| `view_other_rules` | Allow user to view rules from other users |

## Development

### Running Tests

```bash
# Run all tests
make test

# Run tests with verbose output
make test-verbose

# Generate coverage report
make coverage

# Generate HTML coverage report
make coverage-html
```

### Code Quality

```bash
# Format code
make fmt

# Run linter
make lint

# Run go vet
make vet
```

### Building

```bash
# Build for current system
make build

# Build for FreeBSD
make build-freebsd

# Build for OpenBSD
make build-openbsd

# Build for all platforms
make build-all
```

## Logging

The application uses structured JSON logging with zerolog. Logs can be output to:

1. **Logfile** (default) - Configured in `server.logfile`
2. **Stdout** - Use `-foreground` flag

### User Password Generation

The authpf-api supports **Bcrypt** (recommended) and **SHA256** password hashing. Use the `-gen-user-password` flag to generate a bcrypt hash for a new user password.

#### Interactive Mode

Generate a password hash interactively (password input is hidden):

```bash
./authpf-api -gen-user-password
Enter password:
$2a$10$N9qo8uLOic.......
```

#### Piped Mode

Generate a password hash by piping the password:

```bash
echo "your-password" | ./authpf-api -gen-user-password
$2a$10$N9qo8uLOickgx2ZM........
```

#### Adding Users to Configuration

Copy the generated hash and add it to your configuration file (`/usr/local/etc/authpf-api.conf`):

```yaml
rbac:
  users:
    authpf-userX:
      password: $2a$10$abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQR
      role: user
    authpf-admin:
      password: $2a$10$abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQR
      role: admin
```

#### User Management with authpf-api-cli

For comprehensive user and rule management, use the **authpf-api-cli** tool. Refer to the [authpf-api-cli documentation](https://github.com/scd-systems/authpf-api-cli) for detailed instructions on managing users, roles, and permissions.

## Troubleshooting

### Connection Refused
- Verify server is running: `ps aux | grep authpf-api`
- Check bind address and port in configuration
- Ensure firewall allows connections

### Authentication Failed
- Verify username and password are correct
- Check user exists in configuration
- Verify password hash is correct

### Rule Not Loading
- Check pfctl binary path in configuration
- Verify user has permission to run pfctl
- Check authpf rules file exists and is readable
- Review logs for detailed error messages

### Permission Denied
- Verify user role has required permission
- Check RBAC configuration
- Review logs for permission errors

## Contributing

Contributions are welcome! 

Please ensure:

1. Code follows Go conventions
2. All tests pass: `make test`
3. Code is formatted: `make fmt`
4. Linter passes: `make lint`
5. Commit messages are descriptive

## License

See LICENSE file for details.

## Support

For issues, questions, or suggestions, please open an issue on the project repository.
