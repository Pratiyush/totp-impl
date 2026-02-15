# Production-Ready TOTP Library

[![Java](https://img.shields.io/badge/Java-17+-blue.svg)](https://openjdk.org/)
[![RFC](https://img.shields.io/badge/RFC-6238-green.svg)](https://datatracker.ietf.org/doc/html/rfc6238)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A **security-hardened, RFC 6238 compliant** Time-based One-Time Password (TOTP) library for Java.

## Features

- 🔒 **Security First**: Constant-time verification, replay attack prevention, secure memory handling
- 📋 **RFC Compliant**: Full RFC 6238 (TOTP) and RFC 4226 (HOTP) compliance
- 🚀 **Zero Dependencies**: Core functionality requires no external libraries
- ⚡ **High Performance**: Thread-safe, stateless design for concurrent use
- 📱 **App Compatible**: Works with Google Authenticator, Microsoft Authenticator, and others
- 🧪 **Well Tested**: Comprehensive test suite with RFC test vectors

## Quick Start

### Installation

Add to your `pom.xml`:

```xml
<dependency>
    <groupId>com.pratiyush</groupId>
    <artifactId>totp-lib</artifactId>
    <version>1.0.1</version>
</dependency>
```

### Basic Usage

```java
import io.github.pratiyush.totp.Algorithm;
import io.github.pratiyush.totp.SecretGenerator;
import io.github.pratiyush.totp.TOTP;

// Generate a secret for a new user
String secret = SecretGenerator.generate(Algorithm.SHA256);

        // Create TOTP instance
        TOTP totp = TOTP.defaultInstance();

        // Generate a code (for testing/admin purposes)
        String code = totp.generate(secret);

        // Verify a code from user input
        boolean valid = totp.verify(secret, userProvidedCode);
```

### With Replay Protection

```java
import io.github.pratiyush.totp.TOTP;

import java.time.Duration;

// Create TOTP with replay attack prevention
TOTP totp = TOTP.builder()
        .withReplayProtection(Duration.ofMinutes(2))
        .build();

        // Verify with user ID for per-user tracking
        boolean valid = totp.verify(secret, code, userId);
```

### Generate QR Code

```java
import io.github.pratiyush.totp.QRCodeGenerator;

import java.nio.file.Path;

// Generate QR code for authenticator apps
QRCodeGenerator.saveToFile(
        secret, 
    "user@example.com",
            "MyApp",
        Path.of("qr.png"), 
    250
            );

// Or get as Base64 for embedding in HTML
String base64 = QRCodeGenerator.generateBase64(
        secret, "user@example.com", "MyApp", 250);
String html = "<img src='data:image/png;base64," + base64 + "'/>";
```

## Configuration Options

### Algorithm Selection

```java
// SHA-1 (default, widest compatibility)
TOTP totp = TOTP.builder()
    .algorithm(Algorithm.SHA1)
    .build();

// SHA-256 (recommended for new implementations)
TOTP totp = TOTP.builder()
    .algorithm(Algorithm.SHA256)
    .build();

// SHA-512 (maximum security)
TOTP totp = TOTP.builder()
    .algorithm(Algorithm.SHA512)
    .build();
```

### Custom Configuration

```java
TOTPConfig config = TOTPConfig.builder()
    .algorithm(Algorithm.SHA256)
    .digits(8)                    // 6-8 digits
    .periodSeconds(30)            // 15-120 seconds
    .allowedDrift(1)              // Time window tolerance
    .build();

TOTP totp = TOTP.builder()
    .config(config)
    .build();
```

### Preset Configurations

```java
// Default (Google Authenticator compatible)
TOTPConfig.defaultConfig();

// SHA-256 with standard settings
TOTPConfig.sha256Config();

// High security (SHA-512, 8 digits)
TOTPConfig.highSecurityConfig();
```

## Security Features

### Constant-Time Verification

All code comparisons use constant-time algorithms to prevent timing attacks:

```java
// Verification time is independent of whether the code is correct
boolean valid = totp.verify(secret, code);
```

### Replay Attack Prevention

Prevent the same code from being used twice:

```java
// In-memory implementation (single instance)
ReplayGuard guard = new InMemoryReplayGuard(Duration.ofMinutes(2));

// For distributed systems, implement ReplayGuard with Redis/database
public class RedisReplayGuard implements ReplayGuard {
    // Your implementation
}
```

### Secure Memory Handling

Secrets are cleared from memory automatically:

```java
// Internal implementation uses SecureBytes
try (SecureBytes secret = SecureBytes.wrap(secretBytes)) {
    // Use secret
} // Automatically cleared here
```

## API Reference

### TOTP

| Method | Description |
|--------|-------------|
| `generate(secret)` | Generate code for current time |
| `generateAt(secret, instant)` | Generate code for specific time |
| `verify(secret, code)` | Verify a code |
| `verify(secret, code, userId)` | Verify with replay protection |
| `verifyWithDetails(secret, code)` | Verify and get time offset |
| `getSecondsRemaining()` | Seconds until current code expires |
| `getCurrentCounter()` | Current TOTP counter value |

### SecretGenerator

| Method | Description |
|--------|-------------|
| `generate()` | Generate 160-bit secret |
| `generate(algorithm)` | Generate algorithm-appropriate secret |
| `generate(lengthBytes)` | Generate custom length secret |
| `isValid(secret)` | Validate a secret |

### QRCodeGenerator

| Method | Description |
|--------|-------------|
| `generateImage(...)` | Generate BufferedImage |
| `generateBase64(...)` | Generate Base64 PNG |
| `generateDataUri(...)` | Generate data URI |
| `saveToFile(...)` | Save to file |
| `buildOtpauthUri(...)` | Build otpauth:// URI |

## Algorithm Recommendations

| Algorithm | Key Size | Use Case |
|-----------|----------|----------|
| SHA-1 | 20 bytes | Legacy compatibility |
| SHA-256 | 32 bytes | **Recommended for new apps** |
| SHA-512 | 64 bytes | Maximum security requirements |

## Building

```bash
# Compile and run tests
mvn clean verify

# Generate coverage report
mvn jacoco:report

# Build uber-JAR with all dependencies
mvn package -Pshade
```

## Requirements

- Java 17 or higher
- Maven 3.6+ (for building)

## Dependencies

| Dependency | Scope | Purpose |
|------------|-------|---------|
| jSpecify | Required | Null safety annotations |
| ZXing (com.google.zxing) | Optional | QR code generation |
| SLF4J | Optional | Logging |

## Null Safety

This library uses [jSpecify](https://jspecify.dev/) annotations for null safety:

- `@NullMarked` at package level (all types non-null by default)
- `@Nullable` to mark nullable parameters and return types

Compatible with tools like NullAway, Error Prone, and IntelliJ IDEA.

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines and coding standards.

## License

MIT License - see [LICENSE](LICENSE) for details.

## References

- [RFC 6238 - TOTP](https://datatracker.ietf.org/doc/html/rfc6238)
- [RFC 4226 - HOTP](https://datatracker.ietf.org/doc/html/rfc4226)
- [RFC 4648 - Base32](https://datatracker.ietf.org/doc/html/rfc4648)
- [Google Authenticator Key URI Format](https://github.com/google/google-authenticator/wiki/Key-Uri-Format)
- [jSpecify](https://jspecify.dev/)

---

# Markdown Files Consolidation Summary

## Overview

The markdown files in the repository have been consolidated to reduce redundancy while maintaining all essential information. Below is the new structure:

## Files and Their Purpose

### Core Documentation (3 files)

| File | Purpose |
|------|---------|
| **README.md** | Project overview, quick start, and release procedures |
| **CONTRIBUTING.md** | Development guidelines, coding standards, and commit message format |
| **CHANGELOG.md** | Version history and release notes |

## Navigation Structure

```
README.md (Start here)
├── CONTRIBUTING.md (Development & commits)
├── CHANGELOG.md (Version history)
```

## Benefits of Consolidation

✅ **Reduced Redundancy:** No duplicate information across files
✅ **Single Source of Truth:** Main docs (README, CONTRIBUTING) are authoritative
✅ **Better Organization:** Clear navigation and cross-references
✅ **Easier Maintenance:** Updates in one place propagate to all references
✅ **Cleaner Repository:** Only 3 focused files instead of scattered information

## Quick Reference Guide

### For developers starting out:
1. Read **README.md** for overview
2. Check **CONTRIBUTING.md** for coding standards and commit format

### For maintainers preparing a release:
1. See **README.md** "Release & Deployment" section
2. Refer to **pom.xml** for Maven configuration

### For understanding commits:
1. See **CONTRIBUTING.md** "Commit Message Standard" section

## Migration Complete ✓

All markdown files have been consolidated with cross-references in place. No information has been lost—everything is now organized hierarchically with the main documentation files (README, CONTRIBUTING, CHANGELOG) as authoritative sources.
