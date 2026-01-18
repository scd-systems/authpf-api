# AuthPF-API

A RESTful HTTP API for pf user rules.

## Overview

**AuthPF-API** is a Go-based REST API that provides a secure interface for managing pf user rules on FreeBSD and OpenBSD systems. It allows users to activate and deactivate pf rules through HTTP endpoints with JWT token authentication and fine-grained permission control.
The original authpf is "_a user shell for authenticating gateways_" -- [openbsd.org](https://man.openbsd.org/authpf) and is based on SSH logins.
AuthPF-API is an alternative by using HTTP/S to load/unload pf user rules.

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

### Configuration Parameters

#### Defaults Section

| Parameter | Description |
|-----------|-------------|
| `defaults.timeout` | Schedule the maximum timeout for authpf rules (e.g., 30m, 1h). Defines how long the pf rules will be active until the scheduler removes it again. |
| `defaults.pfctlBinary` | Path to the pfctl binary executable (e.g., /sbin/pfctl). Must be accessible by the user running the API. |

#### AuthPF Section

| Parameter | Description |
|-----------|-------------|
| `authpf.userRulesRootfolder` | Root directory where user-specific rule files are stored (e.g., /etc/authpf/users). Each user gets a subdirectory here. |
| `authpf.userRulesFile` | Filename for user rules within the userRulesRootfolder (e.g., authpf.rules). This file is loaded when a user activates their rules. |
| `authpf.anchorName` | Name of the PF anchor to use for rule management (e.g., authpf). Used to organize and manage rules within the packet filter. |
| `authpf.flushFilter` | List of flush targets for pfctl command (nat, queue, ethernet, rules, info, Sources, Reset). Specifies which rule types to clear when flushing. |

#### Server Section

| Parameter | Description |
|-----------|-------------|
| `server.bind` | IP address to bind the server to (e.g., 127.0.0.1 for localhost only). Use 0.0.0.0 to listen on all interfaces. |
| `server.port` | Port number for the HTTP/HTTPS server (e.g., 8080). Ensure the port is not already in use and firewall allows access. |
| `server.ssl.certificate` | Path to SSL certificate file (leave empty to disable SSL). Required for HTTPS connections. |
| `server.ssl.key` | Path to SSL private key file (e.g., key.pem). Must match the certificate and be readable by the server process. |
| `server.jwtSecret` | JWT secret key for token signing - MUST be changed before production deployment. Use a strong, random value for security. |
| `server.jwtTokenTimeout` | JWT token timeout in hours (default: 8 hours if not set). Determines how long authentication tokens remain valid. |
| `server.elevatorMode` | Elevator mode for privilege escalation (none, sudo, or doas). Required when running server as non-root user (recommended). |
| `server.logfile` | Path to the server logfile (e.g., /var/log/authpf-api.log). Ensure the directory exists and is writable by the server process. |

#### RBAC Section

| Parameter | Description |
|-----------|-------------|
| `rbac.roles` | Role definitions with associated permissions (e.g., admin, user). Each role defines what actions users with that role can perform. |
| `rbac.users` | User account definitions with credentials and role assignments. Each user entry includes password hash, assigned role, and numeric user ID. |

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
| `activate_own_rules` | Allow user to activate authpf rules |
| `activate_other_rules` | Allow user to activate rules from other users |
| `deactivate_own_rules` | Allow user to deactivate their own rules |
| `deactivate_other_rules` | Allow user to deactivate rules from other users |
| `view_own_rules` | Allow user to view their own rules status |
| `view_other_rules` | Allow user to view rules status from other users |

## Setup SSL for AuthPF-API

### Create a Self-Signed CA Root and SSL Certificate

Create CA Root Key

```sh
openssl ecparam -genkey -name secp384r1 | openssl ec -aes256 -out rootCA.key
```

Self-Sign CA Root

```sh
openssl req -x509 -new -nodes -key rootCA.key -sha256 -days 3650 -out rootCA.crt
```

Create Server Certificate and sign by the CA Root certificate

```sh
openssl ecparam -genkey -name prime256v1 -noout -out mydomain.com.key
openssl req -new -key mydomain.com.key -out mydomain.com.csr

cat > ./mydomain.com.ext << _EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = mydomain.com
DNS.2 = www.mydomain.com
_EOF

openssl x509 -req -in mydomain.com.csr -CA rootCA.crt -CAkey rootCA.key -CAcreateserial -out mydomain.com.crt -days 397 -sha256 -extfile mydomain.com.ext
```
### Configure authpf-api.conf

```yaml
server:
  ssl: 
    certificate: mydomain.com.crt
    key: mydomain.com.key
```

Restart authpf-api.

Copy over the rootCA.key to the clients to verify the server.

## Elevator Setup

When running authpf-api as non-root user, an elevator setup is required.
AuthPF-API currently supports sudo and doas.

### Sudo Setup

Sudoers File:
```
  Cmnd_Alias AUTHPF_API_COMMANDS = /sbin/pfctl -a authpf/[a-zA-Z0-9_-]* -D user_ip=[0-9.]* -D user_id=[0-9]* -f /etc/authpf/users/[a-zA-Z0-9_-]*/authpf.rules, \
              /sbin/pfctl -a authpf/[a-zA-Z0-9_-]* -F nat, \
              /sbin/pfctl -a authpf/[a-zA-Z0-9_-]* -F rules \
              /sbin/pfctl -a authpf/[a-zA-Z0-9_-]* -F queue \
              /sbin/pfctl -a authpf/[a-zA-Z0-9_-]* -F states
              # add other filters if requires
  %authpf ALL=(root)  NOPASSWD: AUTHPF_API_COMMANDS
```

Configure authpf-api.conf

```yaml
server:
  elevatorMode: sudo
```

### Doas Setup

doas.conf:
```
permit nopass :authpf as root cmd /sbin/pfctl
```

Configure authpf-api.conf

```yaml
server:
  elevatorMode: doas
```

#### Security Considerations

- The doas setup is similar to sudo, but with some restrictions.
Doas does not support regular expressions for command arguments yet.
A solution can be to use the pfctl_wrapper (found under scripts/).

- Why not use flush all (pfctl -a "authpf/user" -Fa) and run each filter flushing separately?
The flush all under FreeBSD 15.0 RELEASE results in an error (pfctl: Operation not supported by device) with ExitCode 1.
It's related to a NETLINK change: https://bugs.freebsd.org/bugzilla/show_bug.cgi?id=291981

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
