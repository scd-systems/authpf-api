# authpf-api.conf(5) - Configuration file for authpf-api

## NAME

**authpf-api.conf** — configuration file for authpf-api

## DESCRIPTION

The **authpf-api.conf** file is a YAML-formatted configuration file for `authpf-api(8)`. It defines all operational parameters including server settings, authentication, pf rule management, and role-based access control.

The default location is `/usr/local/etc/authpf-api.conf`. An alternative path can be specified via the `CONFIG_FILE` environment variable.

## CONFIGURATION SECTIONS
### defaults
Global default settings applied across the application.

**pfctlBinary**
: Path to the `pfctl(8)` binary executable. Must be accessible by the user running `authpf-api(8)`. *(string, required)*

### authpf
AuthPF-specific configuration for rule management and timeouts.

**timeout**
: Maximum timeout for authpf anchors. Defines how long pf rules remain active before the scheduler removes them. Supports duration formats like 30m, 1h, 2d. *(string, required)*

**userRulesRootFolder**
: Root directory where user-specific rule files are stored. Each user gets a subdirectory here. Must be readable and writable by the user running `authpf-api(8)`. *(string, required)*

**userRulesFile**
: Filename for user rules within the userRulesRootFolder. This file is loaded when a user activates their anchors. *(string, required)*

**anchorName**
: Name of the PF anchor to use for rule management. Used to organize and  manage rules within the packet filter. Must match the anchor name configured in `/etc/pf.conf`. *(string, required)*

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
: Specifies the startup anchor loading behavior *(string, optional)*. 
: Valid values: <br>
: `none` - Do not import anchors on startup (default)
: `import` - Import existing anchors from pf. Parses output of `pfctl -sA` and imports all existing  anchors matching the pattern authpf/NAME(USERID).
: `importflush` - Same as import, but removes/flushes anchors immediately after importing to achieve a clean state for startup.

**Limitations**
: 1. UserIP macro value cannot be detected during import. It will be set to "NaN/imported" and has no effect.
: 2. Expire datetime is calculated using `authpf.timeout` and current server time.

**onShutdown**
: Specifies behavior when the API server shuts down. 
: Valid values:
: `none` - Do nothing (default)
: `flushall` - Remove all activated user rules when the API server shuts down

### server
Server configuration including network binding, SSL/TLS, and authentication.

**bind**
: IP address to bind the server to. Use `127.0.0.1` for localhost only, or `0.0.0.0` to listen on all interfaces. *(string, required)*

**port**
: Port number for the HTTP/HTTPS server. Ensure the port is not already in use and that the firewall allows access. *(integer, required)*

**ssl**
: SSL/TLS configuration for HTTPS support. *(object, optional)*

**certificate**
: Path to SSL certificate file. Leave empty to disable SSL and use HTTP only. Required for HTTPS connections. *(string, optional)*

**key**
: Path to SSL private key file. Must match the certificate and be readable by the server process. Required if certificate is specified. *(string, optional)*

**jwtSecret**
: JWT secret key for token signing. MUST be changed before production deployment. Use a strong, random value for security. If not set or empty, a random secret will be generated automatically. `WARNING:` Using the default or a weak secret compromises security. *(string, optional)*

**jwtTokenTimeout**
: JWT token timeout in hours. Determines how long authentication tokens remain valid. Default is 8 hours if not set. *(integer, optional)*

**elevatorMode**
: Elevator mode for privilege escalation. Required when running `authpf-api(8)` as a non-root user. *(string, optional)* 
: Valid values:
: `none` — No privilege escalation (default). Only use if running as root.
: `sudo` — Use `sudo(8)` for privilege escalation. Requires appropriate sudoers configuration.
: `doas` — Use `doas(1)` for privilege escalation. Requires appropriate doas.conf configuration.

**logfile**
: Path to the server logfile. Ensure the directory exists and is writable by the server process. Use `-foreground` flag to log to stdout instead. *(string, required)*

**rbac**
: Role-Based Access Control configuration for users and permissions.

**roles**
: Role definitions with associated permissions. Each role defines what actions users with that role can perform. *(object, required)*

**users**
: User account definitions with credentials and role assignments. Each user entry includes a password hash, assigned role, and optional numeric user ID. *(object, required)*

## AVAILABLE RBAC PERMISSIONS

**activate_own_rules** - Allow user to activate their own authpf rules 
**activate_other_rules** - Allow user to activate rules from other users 
**deactivate_own_rules** - Allow user to deactivate their own rules 
**deactivate_other_rules** - Allow user to deactivate rules from other users 
**view_own_rules** - Allow user to view their own rules status 
**view_other_rules** - Allow user to view rules status from other users

## PASSWORD GENERATION

User passwords must be hashed using bcrypt. Generate a password hash using:

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

Copy the generated hash and add it to the configuration file.

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
    /sbin/pfctl ^-a authpf/([a-zA-Z0-9_-]+)(\([0-9]+\))? -F all$
%_authpf-api ALL=(root)  NOPASSWD: AUTHPF_API_COMMANDS
```

### Configure Doas

Add the following to `/etc/doas.conf`:

```
permit nopass :authpf as root cmd /sbin/pfctl
```

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

### Production Configuration with SSL and Sudo

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

server:
  bind: 0.0.0.0
  port: 443
  ssl:
    certificate: /etc/ssl/certs/authpf-api.crt
    key: /etc/ssl/private/authpf-api.key
  jwtSecret: your-strong-random-secret-here
  jwtTokenTimeout: 12
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
```

## FILES

```
/usr/local/etc/authpf-api.conf — Default configuration file location
/etc/authpf/users — Default root directory for user-specific rule files
/etc/pf.conf — Packet filter configuration file                
/var/log/authpf-api.log — Default logfile location
```

## ENVIRONMENT

```
CONFIG_FILE - Override the default configuration file path
LOG_LEVEL - Set the logging level (debug, info, warn, error)
```

## SEE ALSO

authpf-api(8)
authpf(8),
pfctl(8),
pf(4),
pf.conf(5),
sudo(8),
doas(1)

## HISTORY

The **authpf-api.conf** configuration file format was introduced with `authpf-api(8)` as a YAML-based alternative to traditional shell-based authpf configuration.

## AUTHORS

bofh@scd-systems.net
