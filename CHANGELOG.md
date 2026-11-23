# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.1] - 2026-11-23

### Fixed
- HTTPS startup with an absolute `server.ssl.certificate` / `server.ssl.key` path failed with `readfile server.crt: invalid argument`. Echo v5 resolves `StartTLS` path arguments through an `fs.FS` (`os.DirFS(".")` by default), whose naming rules reject absolute paths and paths with `./` or `..` segments. The key pair is now loaded by `pkg/config` and handed to Echo already parsed, so certificate and key are resolved like every other configured path. 

## [0.4.0] - 2026-11-18

### Fixed
- `jwtToken` timeout validation
- Locking issues affecting extensions that use `ReadOnlyAnchorsDB`
- Imported anchors (`onStartup: import` / `importflush`) no longer store the non-address placeholder `NaN/imported`. They take `rbac.users.<u>.userIp` or are marked `unknown`.
- pfctl flush batch no longer abort at the first failing command, so one broken entry no longer keeps every other user's anchor and table entry loaded
- Shutdown with `onShutdown: flushall` flushes the anchors even when the pf table cleanup failed
- `onStartup: importflush` now revokes the pf table entries too, not only the anchors
- Deactivating a user revokes the address stored for that user instead of the address the deactivation request came from
- A negative, zero or sub-second `authpf.schedulerInterval` panicked the process with `non-positive interval for NewTicker` in the scheduler goroutine, after startup had already succeeded. Such values are now rejected at startup, and the scheduler falls back to 60s if it is ever handed an unusable value.
- Anchor activation no longer leaves the anchor loaded when adding the address to the pf table fails
- A `jwtSecret` shorter than 32 characters, or only whitespace, is rejected at startup
- Update the documentation and man pages

### Added
- Modular extensions system: 
  - Framework-agnostic extension interface
  - Idiomatic lifecycle management via embedded `context.Context`
  - Read-only DB access (`ReadOnlyAnchorsDB`) and global middleware injection (`Middleware()`)
  - New `extensions:` configuration section to enable and configure each extension
  - New command flag `-list-extensions` to display registered extensions
  - List of first extensions:
    - Rate limiting per client IP (`rate-limit`)
    - External Users File (`file-rbac`) with fsnotify hot-reload
    - Metrics export endpoint for Prometheus (`prometheus-metrics`)
  - Extensions Code Repo: `https://github.com/scd-systems/authpf-api-extensions`
- New config parameter `authpf.schedulerInterval` for the scheduler loop interval: a bare number of seconds (`60`) or a Go duration (`90s`, `2m`), bounded to 1s..30 days
- e2e tests for config validation, scheduler interval, rate limiting and anchor DB locking (incl. a static lock guard), plus unit tests for the new error logging

### Changed
- Upgrade all dependencies to their latest versions
- Switch to Go 1.27.4
- Migrate echo web framework from version 4 to version 5
- Improve error logging
- Replace the AnchorDB map with a struct protected by a lock
- All supported configuration parameters are validated at startup; invalid values abort startup and the error identifies the offending parameter
- Build and CI: `make test-race`, `make fmt-check` and `make man` targets, race detector and format gate in the PR workflow

### Removed
- Unused parameter `rbac.users.<name>.userRulesFile`. It was never applied (`authpf.userRulesFile` is used for all users); a leftover entry in an existing configuration file is ignored

## [0.3.0] - 2026-03-16

### ⚠️ Breaking Changes
- Bump Server API Version to 1.2 (authpf-api-cli version >= 0.3.0 required)

### Added
- More Unittests
- Route GET method for /login to validate JWT's from authpf-api-cli
- Static UserIP Support
  Users can be configured to use a pre-defined/static IP address (the remote Client IP will be ignored if set)
- Macro Support
  Users can be configured to have defined macros (see authpf-api.conf.sample)
- PF Table Support
  Tables (global and per user) can be used to add the remote client IP address on activate 
  anchors. The user defined pfTable takes precedence over the global

### Changed
- Project file structure, created packages, refactor and slice code
- Import anchors: existing anchor with username and userid must match
- Rollback: Undo anchor activation in case an anchor activation is failing
- Refactor version information output for CLI/API
- Github Workflow

### Fixed
- Lot of bugs
- Update readme, example and manpages

## [0.2.2] - 2026-02-06

### Added
- Manpages

### Fixed
- Bugs
- Documentation

## [0.2.1] - 2026-01-27

### Added
- Graceful-Shutdown to flush anchors when server gets stopped
- Import anchors on startup
- /info endpoint to get API version response

### Changed
- Improved logging
- Removed clear-text password exchange for user login process
- Switch HSTS by use the secure middleware Handler from echo Framework
- Refactoring

### Fixed
- Documentation

## [0.2.0] - 2026-01-16

### Added
- Activate/Deactivate other users pf rules option
- Automated GitHub Actions workflow for releases
- Configurable JWT Secret and Timeout, set to random if not defined
- UserID in anchors name "authpf/user($UserID)"
- Flag to create bcrypt password for users
- Validation checks
- Wrapper script for doas as elevator mode

### Changed
- Improved configfile loading
- Use bcrypt with salt for user password
- Improved build system with Makefile

### Fixed
- Command pfctl flush all exit error
- AuthPF deactivation bugs
- Security issues

## [0.1.8.4] - 2025-12-01

### Added
- Initial release
- JWT authentication
- RBAC support
- AuthPF rule management

[unreleased]: https://github.com/scd-systems/authpf-api/compare/v0.4.1...HEAD
[0.4.1]: https://github.com/scd-systems/authpf-api/compare/v0.3.0...v0.4.1
[0.4.0]: https://github.com/scd-systems/authpf-api/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/scd-systems/authpf-api/compare/v0.2.2...v0.3.0
[0.2.2]: https://github.com/scd-systems/authpf-api/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/scd-systems/authpf-api/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/scd-systems/authpf-api/compare/v0.1.8.4...v0.2.0
[0.1.8.4]: https://github.com/scd-systems/authpf-api/releases/tag/v0.1.8.4
