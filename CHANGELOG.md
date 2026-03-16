# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - 2026-03-16

### ⚠️ Breaking Changes
- Bump Server API Version to 1.2 (authpf-api-cli version >= 0.2.4 required)

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

## [0.1.0] - 2025-12-01

### Added
- Initial release
- JWT authentication
- RBAC support
- AuthPF rule management

[unreleased]: https://github.com/scd-systems/authpf-api/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/scd-systems/authpf-api/compare/v0.2.0...v0.2.1
[0.2.2]: https://github.com/scd-systems/authpf-api/compare/v0.2.0...v0.2.1
[0.2.1]: https://github.com/scd-systems/authpf-api/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/scd-systems/authpf-api/compare/v0.1.9...v0.2.0
