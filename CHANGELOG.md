# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.1.1-dev]

### Added

### Changed
- removed clear-text password exchange for user login process
- improved logging

### Fixed
- documentation: sudo examples

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

[unreleased]: https://github.com/scd-systems/authpf-api/compare/v0.2.0...HEAD
[0.2.1]: https://github.com/scd-systems/authpf-api/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/scd-systems/authpf-api/compare/v0.1.9...v0.2.0
