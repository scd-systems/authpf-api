# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- More unittests
- Support PF Tables 
- Support option for no-ip (authpf-noip)
- Clear pf anchors on startup
- Import existing pf anchors on startup 
- Add user defined pf macros

### Changed
- Use syscalls to modify pf anchors instead wrap pfctl command

### Fixed
- Bug fixes

## [0.2.0] - 2026-01-12

### Added
- Activate/Deactivate other users pf rules option
- Automated GitHub Actions workflow for releases
- Configureable JWT Secret, set a random if not defined 
- UserID in anchors name "authpf/user($UserID)"
- Flag to create bcrypt password for users

### Changed
- Improved configfile loading
- Use bcrypt with salt for user password
- Improved build system with Makefile

### Fixed
- Command pfctl flush all exit error
- AuthPF deactivation bugs

## [0.1.0] - 2025-12-01

### Added
- Initial release
- JWT authentication
- RBAC support
- AuthPF rule management
