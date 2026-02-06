# authpf-api(8) - RESTful HTTP API for managing pf user rules

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
: Generate a bcrypt-hashed password for user authentication. The password is hashed using SHA256 first, then bcrypt. Can be used interactively or with piped input.

## ENVIRONMENT

**CONFIG_FILE**
: Path to the configuration file. Defaults to `/usr/local/etc/authpf-api.conf` if not set.

**LOG_LEVEL**
: Set the logging level. Valid values are: `debug`, `info`, `warn`, `error`. Default is `info`.

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
: `authpf_username` - Activate rules for another user (requires appropriate permissions)
: `timeout` — Override the default timeout (e.g., 30m, 1h)

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
: `authpf_username` - Deactivate rules for another user (requires appropriate permissions)

**Response (202 Accepted):**
```json
{
  "status": "queued",
  "user": "authpf-user1",
  "msg": "authpf anchor is being unloaded"
}
```

#### GET /api/v1/authpf/all

Get status of all activated rules.

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

Delete all activated rules (admin only).

**Response (200 OK):**
```json
{
  "status": "cleared"
}
```

## EXAMPLES

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

### Run in foreground with debug logging

```sh
LOG_LEVEL=debug authpf-api -foreground
```

### Check version

```sh
authpf-api -version
```

## SETUP

Before using **authpf-api**, ensure that the authpf anchors are configured in `/etc/pf.conf`:

```
nat-anchor "authpf/*"
rdr-anchor "authpf/*"
binat-anchor "authpf/*"
anchor "authpf/*"
```

Verify that the anchor name in the configuration file matches the `anchorName` setting (default: authpf).

## FILES

```
/usr/local/etc/authpf-api.conf — Default configuration file
/var/log/authpf-api.log — Default logfile location
/etc/authpf/users — Default root directory for user-specific rule files
/etc/pf.conf — Packet filter configuration file
```
## SEE ALSO

authpf-api.conf(5),
authpf(8),
file(1),
pfctl(8),
pf(4),
sudo(8),
doas(1)

## HISTORY

**authpf-api** was created as an alternative to the traditional `authpf(8)` shell, providing HTTP/HTTPS-based rule management instead of SSH-based authentication.

## AUTHORS

bofh@scd-systems.net
