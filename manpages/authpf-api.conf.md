# authpf-api.conf(5) - Configuration file for authpf-api

## NAME

**authpf-api.conf** — configuration file for authpf-api

## DESCRIPTION

The **authpf-api.conf** file is a YAML-formatted configuration file for `authpf-api(1)`. It defines all operational parameters including server settings, authentication, pf rule management, and role-based access control.

The default location is `/usr/local/etc/authpf-api.conf`. An alternative path can be specified via the `CONFIG_FILE` environment variable or the **-configFile** / **-c** command-line flags.

## CONFIGURATION SECTIONS

### defaults

Global default settings applied across the application.

**pfctlBinary**
: Path to the `pfctl(8)` binary executable. Must be accessible by the user running `authpf-api(1)`. *(string, required)*

### authpf

AuthPF-specific configuration for rule management and timeouts.

**timeout**
: Maximum timeout for authpf anchors. Defines how long pf rules remain active before the scheduler removes them. Supports duration formats like `30m`, `1h`, `2d`. *(string, required)*

**userRulesRootFolder**
: Root directory where user-specific rule files are stored. Each user gets a subdirectory here. Must be readable by the user running `authpf-api(1)`. *(string, required)*

**userRulesFile**
: Filename for user rules within the `userRulesRootFolder`. This file is loaded when a user activates their anchors. Can be overridden per user via `rbac.users.<name>.userRulesFile`. *(string, required)*

**anchorName**
: Name of the PF anchor to use for rule management. Used to organize and manage rules within the packet filter. Must match the anchor name configured in `/etc/pf.conf`. *(string, required)*

**flushFilter**
: List of flush targets for `pfctl(8)` commands. Specifies which rule types to clear when flushing. *(array of strings, required)*
: Valid values:
` `  `nat`
` `  `queue`
` `  `ethernet`
` `  `rules`
` `  `info`
` `  `Sources`
` `  `Reset`

**onStartup**
: Specifies the startup anchor loading behavior. *(string, optional)*
: Valid values:
: `none` — Do not import anchors on startup (default)
: `import` — Import existing anchors from pf. Parses the output of `pfctl -sA` and imports all existing anchors matching the pattern `authpf/NAME(USERID)`. Note: anchors without a numeric user ID suffix (e.g. `authpf/user` without `(2000)`) are not imported.
: `importflush` — Same as `import`, but removes/flushes all anchors immediately after importing to achieve a clean state on startup.

**Limitations of import:**
: 1. The `user_ip` macro value cannot be detected during import. It will be set to `NaN/imported` and has no functional effect. Deactivation works without a valid IP address.
: 2. The expiry datetime is calculated from `authpf.timeout` and the current server time at import.

**onShutdown**
: Specifies behavior when the API server shuts down. *(string, optional)*
: Valid values:
: `none` — Do nothing (default)
: `flushall` — Remove all activated user rules when the API server shuts down

**pfTable**
: Name of a global pf table used to track active user IP addresses. When set, the user's IP is added to this table on anchor activation and removed on deactivation. The table must be declared as `persist` in `/etc/pf.conf` before starting `authpf-api(1)`. Leave empty to disable. Can be overridden per user via `rbac.users.<name>.pfTable`. *(string, optional)*

### server

Server configuration including network binding, SSL/TLS, and authentication.

**bind**
: IP address to bind the server to. Use `127.0.0.1` for localhost only, or `0.0.0.0` to listen on all interfaces. *(string, required)*

**port**
: Port number for the HTTP/HTTPS server. Ensure the port is not already in use and that the firewall allows access. *(integer, required)*

**ssl**
: SSL/TLS configuration for HTTPS support. *(object, optional)*

**ssl.certificate**
: Path to the SSL certificate file. Leave empty to disable SSL and use plain HTTP. Required for HTTPS connections. *(string, optional)*

**ssl.key**
: Path to the SSL private key file. Must match the certificate and be readable by the server process. Required if `ssl.certificate` is specified. *(string, optional)*

**jwtSecret**
: JWT secret key for token signing. MUST be changed before production deployment. Use a strong, random value for security. If not set or empty, a random secret is generated automatically on each startup — this means all tokens are invalidated on restart. *(string, optional)*

**jwtTokenTimeout**
: JWT token validity duration. Determines how long authentication tokens remain valid. Supports duration formats like `30m`, `8h`, `24h`. Default is `8h` if not set. *(string, optional)*

**elevatorMode**
: Elevator mode for privilege escalation. Required when running `authpf-api(1)` as a non-root user. *(string, optional)*
: Valid values:
: `none` — No privilege escalation (default). Only use if running as root.
: `sudo` — Use `sudo(8)` for privilege escalation. Requires appropriate sudoers configuration.
: `doas` — Use `doas(1)` for privilege escalation. Requires appropriate doas.conf configuration.

**logfile**
: Path to the server logfile. Ensure the directory exists and is writable by the server process. Use the `-foreground` flag to log to stdout instead. *(string, required)*

### rbac

Role-Based Access Control configuration for users and permissions.

**rbac.roles**
: Role definitions with associated permissions. Each role defines what actions users with that role can perform. *(object, required)*

**rbac.roles.\<name\>.permissions**
: List of permission strings assigned to this role. See **AVAILABLE RBAC PERMISSIONS** below. *(array of strings, required)*

**rbac.users**
: User account definitions with credentials and role assignments. *(object, required)*

**rbac.users.\<name\>.password**
: Bcrypt password hash for this user. Generate with `authpf-api -gen-user-password`. *(string, required)*

**rbac.users.\<name\>.role**
: Role assigned to this user. Must match a key defined under `rbac.roles`. *(string, required)*

**rbac.users.\<name\>.userId**
: Numeric user ID used as the pf anchor suffix (e.g. `authpf/username(1001)`). Defaults to `0` if not set. *(integer, optional)*

**rbac.users.\<name\>.userIp**
: Pin a static IP address passed as the `user_ip` macro to `pfctl`. If omitted, the remote client IP of the HTTP request is used automatically. When set, the configured value is always used regardless of the actual source IP. *(string, optional)*

**rbac.users.\<name\>.userRulesFile**
: Override the global `authpf.userRulesFile` for this specific user. If set, this filename is used instead of the global default when loading this user's anchor rules. *(string, optional)*

**rbac.users.\<name\>.macros**
: Map of arbitrary key/value pairs passed as additional `-D key=value` arguments to `pfctl` when the user's anchor is loaded. Each macro must also be declared in the user's pf rules file. Macro keys and values are validated to contain only alphanumeric characters, underscores, dots, and hyphens. The reserved keys `user_ip` and `user_id` must not be redefined here if `userIp` or `userId` are already set. *(map of string to string, optional)*

**rbac.users.\<name\>.pfTable**
: Override the global `authpf.pfTable` for this specific user. If set, this user's IP is tracked in this table instead of the global one. The table must be declared as `persist` in `/etc/pf.conf`. *(string, optional)*

## AVAILABLE RBAC PERMISSIONS

**activate_own_rules**
: Allow user to activate their own authpf rules.

**activate_other_rules**
: Allow user to activate rules for other users (via `authpf_username` query parameter).

**deactivate_own_rules**
: Allow user to deactivate their own rules.

**deactivate_other_rules**
: Allow user to deactivate rules for other users (via `authpf_username` query parameter). Also required for `DELETE /api/v1/authpf/all`.

**view_own_rules**
: Allow user to view their own rules status via `GET /api/v1/authpf/all`.

**view_other_rules**
: Allow user to view rules status for all users via `GET /api/v1/authpf/all`.

## PF TABLE SUPPORT

**authpf-api** can automatically track active user IPs in a pf table, similar to the original `authpf(8)` behaviour. This allows pf rules to reference the set of currently authenticated users by table name.

When a user's anchor is **activated**, their `user_ip` is added to the configured pf table via `pfctl -t <table> -T add <ip>`. When a user's anchor is **deactivated**, their IP is removed via `pfctl -t <table> -T delete <ip>`. On startup, **authpf-api** verifies that all configured tables exist — this check is fatal and prevents the server from starting if a table is missing.

**Priority** (highest to lowest):
```
rbac.users.<name>.pfTable  →  authpf.pfTable  →  no table management
```

The table must be declared as `persist` in `/etc/pf.conf`:

```
table <authpf_users> persist
```

Without `persist`, pf removes the table when it becomes empty, causing subsequent `pfctl -T add` calls to fail.

**Error behaviour:**

| Operation | On failure |
|---|---|
| Add IP on activate | Fatal — HTTP 500 returned, anchor is not activated |
| Remove IP on deactivate | Warn only — logged, anchor is still flushed |
| Remove IP on shutdown / deactivate-all | Warn only — logged, all anchors are still flushed |
| Table existence check on startup | Fatal — server refuses to start |

## PASSWORD GENERATION

User passwords must be hashed using bcrypt. The `-gen-user-password` flag performs a two-step hash: SHA256 followed by bcrypt. The API login endpoint expects the password to be sent as a SHA256 hash.

```sh
authpf-api -gen-user-password
Enter password:
$2a$10$N9qo8uLOickgx2ZM.......
```

Or via pipe:

```sh
echo -n "your-password" | authpf-api -gen-user-password
$2a$10$N9qo8uLOickgx2ZM.......
```

Copy the generated hash and add it to the configuration file under `rbac.users.<name>.password`.

## ELEVATOR SETUP

When running **authpf-api** as a non-root user, an elevator setup is required. **authpf-api** supports both `sudo(8)` and `doas(1)`.

### Configure Sudo

Add the following to the sudoers file:

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

The three pf table rules (`-T add`, `-T delete`, `-T show`) are only required when `authpf.pfTable` or any `rbac.users.<name>.pfTable` is configured. They cover both IPv4 and IPv6 addresses.

When using user-defined `macros`, the sudoers `Cmnd_Alias` must be updated to allow the additional `-D` arguments. Use a broad regex pattern to cover all macro key/value pairs:

```
/sbin/pfctl ^-a authpf/([a-zA-Z0-9_-]+)(\([0-9]+\))? \
    -D [a-zA-Z0-9_-]+=[a-zA-Z0-9_.+-]+ \
    -f /etc/authpf/users/[a-zA-Z0-9_-]+/authpf.rules$
```

### Configure Doas

Add the following to `/etc/doas.conf`:

```
permit nopass :authpf as root cmd /sbin/pfctl
```

For a more restrictive setup, use the `pfctl_wrapper` script (found under `scripts/`) and configure `defaults.pfctlBinary` to point to it:

```
permit nopass :authpf as root cmd /usr/local/sbin/pfctl_wrapper
```

**Note:** `doas(1)` does not support regular expressions for command arguments. The broad `cmd /sbin/pfctl` rule allows all pfctl invocations. Use the `pfctl_wrapper` for tighter control.

**Note:** On FreeBSD 15.0, `pfctl -Fa` (flush all) may return an error (`Operation not supported by device`) due to a NETLINK change. Run each flush filter separately instead of using `all`.

## EXAMPLES

### Minimal Configuration

```yaml
defaults:
  pfctlBinary: /sbin/pfctl

authpf:
  timeout: 30m
  userRulesRootFolder: /etc/authpf/users
  userRulesFile: authpf.rules
  anchorName: authpf
  flushFilter:
    - nat
    - rules
  onStartup: none
  onShutdown: none

server:
  bind: 127.0.0.1
  port: 8080
  logfile: /var/log/authpf-api.log

rbac:
  roles:
    user:
      permissions:
        - activate_own_rules
        - deactivate_own_rules
        - view_own_rules
  users:
    authpf-user1:
      password: $2a$10$abcdefg.....
      role: user
```

### Production Configuration with SSL, Sudo, and PF Table

```yaml
defaults:
  pfctlBinary: /sbin/pfctl

authpf:
  timeout: 1h
  userRulesRootFolder: /etc/authpf/users
  userRulesFile: authpf.rules
  anchorName: authpf
  flushFilter:
    - nat
    - queue
    - rules
  onStartup: importflush
  onShutdown: flushall
  pfTable: authpf_users

server:
  bind: 0.0.0.0
  port: 443
  ssl:
    certificate: /etc/ssl/certs/authpf-api.crt
    key: /etc/ssl/private/authpf-api.key
  jwtSecret: your-strong-random-secret-here
  jwtTokenTimeout: 12h
  elevatorMode: sudo
  logfile: /var/log/authpf-api.log

rbac:
  roles:
    admin:
      permissions:
        - activate_own_rules
        - activate_other_rules
        - deactivate_own_rules
        - deactivate_other_rules
        - view_own_rules
        - view_other_rules
    user:
      permissions:
        - activate_own_rules
        - deactivate_own_rules
        - view_own_rules
  users:
    authpf-admin:
      password: $2a$10$abcdefg.....
      role: admin
      userId: 1000
    authpf-user1:
      password: $2a$10$hijklmni.....
      role: user
      userId: 1001
      userIp: 192.168.0.10
      userRulesFile: custom.rules
      pfTable: custom_table_user1
      macros:
        server_1_port: 22
        server_1_addr: 10.127.2.1
```

## FILES

```
/usr/local/etc/authpf-api.conf — Default configuration file location
/etc/authpf/users              — Default root directory for user-specific rule files
/etc/pf.conf                   — Packet filter configuration file
/var/log/authpf-api.log        — Default logfile location
```

## ENVIRONMENT

**CONFIG_FILE**
: Override the default configuration file path. Overridden by the **-configFile** / **-c** flags.

**LOG_LEVEL**
: Set the logging level (`debug`, `info`, `warn`, `error`, `fatal`). Overridden by the **-v** flag.

## SEE ALSO

authpf-api(1),
authpf(8),
pfctl(8),
pf(4),
pf.conf(5),
sudo(8),
doas(1)

## HISTORY

The **authpf-api.conf** configuration file format was introduced with `authpf-api(1)` as a YAML-based alternative to traditional shell-based authpf configuration.

## AUTHORS

bofh@scd-systems.net
