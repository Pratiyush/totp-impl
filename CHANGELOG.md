# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-02-05

### Added
- **Production Release**: Full RFC 6238 compliance with security hardening
- jSpecify 1.0.0 integration for null safety annotations
- `@NullMarked` package-level annotations
- Comprehensive test suite with 139+ tests
- `README.md` with API reference and examples
- `SECURITY.md` with threat model and best practices

### Security
- Constant-time code verification to prevent timing attacks
- Replay attack prevention via `ReplayGuard` interface
- Secure memory handling with `SecureBytes` wrapper

## [0.9.0] - 2026-02-04

### Added
- `QRCodeGenerator` for authenticator app integration
- Multiple output formats: BufferedImage, Base64, data URI, file
- `otpauth://` URI builder with full RFC compliance

### Changed
- Improved error messages in `TOTPException`

## [0.8.0] - 2026-02-03

### Added
- `InMemoryReplayGuard` with automatic expiration
- Thread-safe implementation using `ConcurrentHashMap`
- Configurable retention period
- Background cleanup scheduler

### Fixed
- Race condition in concurrent code verification

## [0.7.0] - 2026-02-02

### Added
- `ReplayGuard` interface for extensibility
- `TOTP.Builder` with fluent API
- `withReplayProtection()` convenience method

### Changed
- Made `TOTP` class immutable

## [0.6.0] - 2026-02-01

### Added
- `SecretGenerator` with algorithm-specific key sizes
- Entropy validation (minimum 128 bits)
- Thread-safe `SecureRandom` usage

### Security
- Raw secret bytes cleared after Base32 encoding

## [0.5.0] - 2026-01-31

### Added
- `TOTPConfig` immutable configuration class
- Builder pattern with validation
- Preset configurations: `defaultConfig()`, `sha256Config()`, `highSecurityConfig()`

### Changed
- Extracted configuration from `TOTP` class

## [0.4.0] - 2026-01-30

### Added
- `SecureBytes` wrapper for sensitive data
- `AutoCloseable` implementation for try-with-resources
- Automatic memory clearing on close

### Security
- Secrets no longer remain in memory after use

## [0.3.0] - 2026-01-29

### Added
- `Base32Codec` with RFC 4648 compliance
- Zero-dependency implementation
- Case-insensitive decoding
- Padding handling (optional)

### Removed
- Apache Commons Codec dependency

## [0.2.0] - 2026-01-28

### Added
- `Algorithm` enum with SHA-1, SHA-256, SHA-512 support
- `TOTPException` with error codes
- `HMACProvider` for thread-safe HMAC computation

### Changed
- Improved algorithm validation

## [0.1.0] - 2026-01-27

### Added
- Initial `TOTPEngine` implementation
- RFC 6238 TOTP generation
- RFC 4226 HOTP dynamic truncation
- `TOTPClock` for testable time handling
- Basic project structure with Maven
- JUnit 5 test framework setup

---

**Author**: Pratiyush Kumar Singh  
**License**: MIT
