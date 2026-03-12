# authpf-api(1) - RESTful HTTP API for managing pf user rules

## NAME

**authpf-api** — RESTful HTTP API for managing pf user rules

## SYNOPSIS

**authpf-api** [*OPTIONS*]

## DESCRIPTION

**authpf-api** is a Go-based REST API that provides a secure interface for managing pf user rules on FreeBSD and OpenBSD systems. It allows users to activate and deactivate pf rules through HTTP endpoints with JWT token authentication and fine-grained permission control.

The original `authpf(8)` is a user shell for authenticating gateways based on SSH logins. **authpf-api** is an alternative implementation using HTTP/HTTPS to load and unload pf user rules.

## OPTIONS

**-foreground**
: Log to stdout instead of the configured logfile. Useful for debugging and running in the foreground during development or testing.

**-version**
: Display the version information and exit.

**-gen-user-password**
: Generate a bcrypt-hashed password for user authentication. The password is first hashed with SHA256, then with bcrypt. Can be used interactively or with piped input. Note: the API login endpoint expects the password to be sent as a SHA256 hash.

**-configFile** *path*
: Path to the configuration file. Overrides the `CONFIG_FILE` environment variable and the compiled-in default.

**-c** *path*
: Short form of **-configFile**. Takes precedence over **-configFile** if both are specified.

**-v** *level*
: Set the log level. Valid values are: `debug`, `info`, `warn`, `error`, `fatal`. Overrides the `LOG_LEVEL` environment variable.

## ENVIRONMENT

**CONFIG_FILE**
: Path to the configuration file. Defaults to `/usr/local/etc/authpf-api.conf` if not set. Overridden by the **-configFile** / **-c** flags.

**LOG_LEVEL**
: Set the logging level. Valid values are: `debug`, `info`, `warn`, `error`, `fatal`. Default is `info`. Overridden by the **-v** flag.

## CONFIGURATION

**authpf-api** is configured via a YAML configuration file, typically located at `/usr/local/etc/authpf-api.conf`. See `authpf-api.conf(5)` for detailed configuration options.

## API ENDPOINTS

### Authentication

#### POST /login

Authenticate a user and obtain a JWT token.

**Request body:**
```json
{
  "username": "authpf-user1",
  "password": "SHA256_HASH"
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

#### POST /api/v1/authpf/activate

Activate pf rules for the authenticated user.

Query parameters:
: `authpf_username` — Activate rules for another user (requires `activate_other_rules` permission)
: `timeout` — Override the default timeout (e.g., `30m`, `1h`)

**Response (201 Created):**
```json
{
  "status": "activated",
  "user": "authpf-user1",
  "msg": "authpf anchor is being loaded"
}
```

#### DELETE /api/v1/authpf/activate

Deactivate pf rules for the authenticated user.

Query parameters:
: `authpf_username` — Deactivate rules for another user (requires `deactivate_other_rules` permission)

**Response (202 Accepted):**
```json
{
  "status": "queued",
  "user": "authpf-user1",
  "msg": "authpf anchor is being unloaded"
}
```

#### GET /api/v1/authpf/all

Get status of all activated rules. Requires `view_own_rules` permission; `view_other_rules` is required to see other users' rules.

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

#### DELETE /api/v1/authpf/all

Delete all activated rules. Requires `deactivate_other_rules` permission (admin only).

**Response (200 OK):**
```json
{
  "status": "cleared"
}
```

## PASSWORD GENERATION

**authpf-api** uses a two-step hashing scheme: the plain-text password is first hashed with SHA256, then the SHA256 digest is hashed with bcrypt and stored in the configuration file. When logging in, the client must send the SHA256 hash of the plain-text password — not the plain-text password itself.

### Generate a user password

```sh
authpf-api -gen-user-password
Enter password:
$2a$10$N9qo8uLOickgx2ZM.......
```

### Generate password via pipe

```sh
echo -n "your-password" | authpf-api -gen-user-password
$2a$10$N9qo8uLOickgx2ZM.......
```

## EXAMPLES

### Run in foreground with debug logging

```sh
LOG_LEVEL=debug authpf-api -foreground
```

### Run with a custom config file

```sh
authpf-api -c /etc/authpf-api/authpf-api.conf
```

### Check version

```sh
authpf-api -version
```

## SETUP

### PF Configuration

Before using **authpf-api**, ensure that the authpf anchors are configured in `/etc/pf.conf`:

```
nat-anchor "authpf/*"
rdr-anchor "authpf/*"
binat-anchor "authpf/*"
anchor "authpf/*"
```

Verify that the anchor name in the configuration file matches the `anchorName` setting (default: `authpf`).

If PF table support is enabled, declare the table as `persist` in `/etc/pf.conf` so it survives becoming empty:

```
table <authpf_users> persist
```

### SSL Setup

To enable HTTPS, generate a certificate and key and configure them in `authpf-api.conf(5)`. Example using a self-signed CA:

```sh
# Create CA root key and self-sign
openssl ecparam -genkey -name secp384r1 | openssl ec -aes256 -out rootCA.key
openssl req -x509 -new -nodes -key rootCA.key -sha256 -days 3650 -out rootCA.crt

# Create server key and CSR
openssl ecparam -genkey -name prime256v1 -noout -out server.key
openssl req -new -key server.key -out server.csr

# Sign the server certificate
openssl x509 -req -in server.csr -CA rootCA.crt -CAkey rootCA.key \
    -CAcreateserial -out server.crt -days 397 -sha256
```

Then set in `authpf-api.conf`:

```yaml
server:
  ssl:
    certificate: /etc/ssl/certs/server.crt
    key: /etc/ssl/private/server.key
```

### Elevator Setup

When running **authpf-api** as a non-root user, privilege escalation is required to execute `pfctl(8)`. See `authpf-api.conf(5)` for full configuration details.

**Configure Sudo** — add to the sudoers file:

```
Cmnd_Alias AUTHPF_API_COMMANDS = /sbin/pfctl -sA, \
    /sbin/pfctl ^-a authpf/([a-zA-Z0-9_-]+)(\([0-9]+\))? \
        -D user_ip=[0-9.]+ -D user_id=[0-9]+ \
        -f /etc/authpf/users/[a-zA-Z0-9_-]+/authpf.rules$, \
    /sbin/pfctl ^-a authpf/([a-zA-Z0-9_-]+)(\([0-9]+\))? -F nat$, \
    /sbin/pfctl ^-a authpf/([a-zA-Z0-9_-]+)(\([0-9]+\))? -F rules$, \
    /sbin/pfctl ^-a authpf/([a-zA-Z0-9_-]+)(\([0-9]+\))? -F queue$, \
    /sbin/pfctl ^-a authpf/([a-zA-Z0-9_-]+)(\([0-9]+\))? -F states$, \
    /sbin/pfctl ^-a authpf/([a-zA-Z0-9_-]+)(\([0-9]+\))? -F Tables$, \
    /sbin/pfctl ^-a authpf/([a-zA-Z0-9_-]+)(\([0-9]+\))? -F all$, \
    /sbin/pfctl ^-t [a-zA-Z0-9_]+ -T add [0-9a-fA-F:.]+$, \
    /sbin/pfctl ^-t [a-zA-Z0-9_]+ -T delete [0-9a-fA-F:.]+$, \
    /sbin/pfctl ^-t [a-zA-Z0-9_]+ -T show$
%_authpf-api ALL=(root)  NOPASSWD: AUTHPF_API_COMMANDS
```

The three pf table rules are only required when `authpf.pfTable` or any `rbac.users.<name>.pfTable` is configured.

**Configure Doas** — add to `/etc/doas.conf`:

```
permit nopass :authpf as root cmd /sbin/pfctl
```

## FILES

```
/usr/local/etc/authpf-api.conf — Default configuration file
/var/log/authpf-api.log        — Default logfile location
/etc/authpf/users              — Default root directory for user-specific rule files
/etc/pf.conf                   — Packet filter configuration file
```

## SEE ALSO

authpf-api.conf(5),
authpf(8),
pfctl(8),
pf(4),
pf.conf(5),
sudo(8),
doas(1)

## HISTORY

**authpf-api** was created as an alternative to the traditional `authpf(8)` shell, providing HTTP/HTTPS-based rule management instead of SSH-based authentication.

## AUTHORS

bofh@scd-systems.net
