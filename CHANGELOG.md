# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- More unittests
- Multiple activate/deactivate support for different UserIP
- PF Tables support
- Clear AuthPF anchors on startup
- Import existing AuthPF anchors states on startup 

### Changed

### Fixed
- Bug fixes

## [0.2.0] - 2026-01-10

### Added
- Activate/Deactivate other user rules option
- Automated GitHub Actions workflow for releases
- Configureable JWT Secret, set a random if not defined 
- UserID in anchors name "authpf/user($UserID)"

### Changed
- Improve configfile loading
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
