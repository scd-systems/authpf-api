# pfctl_wrapper

A secure wrapper for pfctl commands designed to work with authpf-api and doas privilege elevation.
Cause of missing regular expressions for command arguments in doas, this wrapper provide a secure alternative to allow all pfctl command parameters.
This program validates all parameters (anchors, defines, filters, and file paths) to prevent command injection and path traversal attacks. It enforces strict whitelisting of anchor formats, IP addresses, and file locations within `/etc/authpf`, ensuring safe execution of pfctl rules management without exposing the system to shell metacharacter expansion or escape attempts. Use with doas in sudoers-like configuration for privilege-separated pfctl rule activation and deactivation.

## Build

```sh
go build -o pfctl_wrapper
```

## Usage

Help

```sh
pfctl_wrapper -h
```

Install and configure doas:

```sh
install -m 0755 -o root -g authpf pfctl_wrapper /usr/local/sbin/pfctl_wrapper
echo 'permit nopass :authpf as root cmd /usr/local/bin/pfctl_wrapper' >> /usr/local/etc/doas.conf
```

Configure authpf-api:

```yaml
defaults:
  timeout: 30m
  pfctlBinary: /usr/local/bin/pfctl_wrapper
  : # removed for brevity
server:
  elevatorMode: doas
  : # removed for brevity
```