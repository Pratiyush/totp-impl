# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |

## Security Features

This library implements several security measures to protect TOTP operations:

### 1. Constant-Time Verification

All code comparisons use `MessageDigest.isEqual()` which provides constant-time comparison. This prevents timing attacks where an attacker could deduce the correct code by measuring response times.

### 2. Replay Attack Prevention

The `ReplayGuard` interface and `InMemoryReplayGuard` implementation prevent the same TOTP code from being used multiple times within its validity window.

**Recommendation**: For distributed systems, implement `ReplayGuard` using Redis or a similar distributed cache.

### 3. Secure Memory Handling

The `SecureBytes` class ensures that secret keys are:
- Cleared from memory when no longer needed
- Not accidentally logged or serialized
- Properly handled in try-with-resources blocks

**Note**: Due to JVM limitations, we cannot guarantee that the garbage collector hasn't made copies. For highly sensitive environments, consider using a Hardware Security Module (HSM).

### 4. Input Validation

All inputs are strictly validated:
- Secrets must be at least 26 Base32 characters (130 bits of entropy)
- Codes must match the expected digit count
- Configuration parameters are range-checked

### 5. Exception Safety

Exceptions never contain sensitive data:
- Secret values are never included in error messages
- Error codes enable programmatic handling without parsing messages

## Best Practices

### Secret Storage

1. **Never log secrets** - Use the SecureBytes wrapper
2. **Encrypt at rest** - Store secrets encrypted in your database
3. **Limit access** - Secrets should only be accessible to the authentication service
4. **Rotate periodically** - Implement secret rotation for long-lived accounts

### Implementation

```java
// ✅ Good: Use try-with-resources
try (SecureBytes secret = SecureBytes.wrap(getSecretFromDatabase())) {
    return engine.verify(secret.getBytes(), code);
}

// ❌ Bad: Secrets remain in memory
byte[] secret = getSecretFromDatabase();
boolean result = engine.verify(secret, code);
// secret is never cleared!
```

### Replay Protection

```java
// ✅ Good: Enable replay protection with user context
TOTP totp = TOTP.builder()
    .withReplayProtection(Duration.ofMinutes(2))
    .build();
totp.verify(secret, code, userId);

// ⚠️ Caution: Without user ID, codes could be shared between users
totp.verify(secret, code);
```

### Algorithm Selection

- **SHA-1**: Use only for compatibility with existing systems
- **SHA-256**: Recommended for new implementations
- **SHA-512**: Use when security requirements demand maximum margin

## Threat Model

### Covered Threats

| Threat | Mitigation |
|--------|------------|
| Timing attacks | Constant-time comparison |
| Replay attacks | ReplayGuard implementation |
| Memory disclosure | SecureBytes auto-clearing |
| Brute force | 6+ digit codes, rate limiting (external) |
| Clock drift | Configurable drift tolerance |

### Out of Scope

| Threat | Recommendation |
|--------|----------------|
| Secret theft from database | Encrypt secrets at rest |
| Man-in-the-middle | Use TLS for all communications |
| Phishing | User education, hardware tokens |
| Device compromise | Beyond TOTP scope |

## Reporting Vulnerabilities

If you discover a security vulnerability, please:

1. **Do not** open a public issue
2. Email security details to: security@pratiyush.com
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Any suggested fixes

We will respond within 48 hours and work with you to address the issue.

## Security Changelog

### v1.0.0
- Initial release with constant-time verification
- Replay attack prevention via ReplayGuard
- SecureBytes for memory protection
- RFC 6238 compliance verified with test vectors
