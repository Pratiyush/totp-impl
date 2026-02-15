# Contributing to Production-Ready TOTP Library

Thank you for your interest in contributing! We welcome bug reports, feature requests, and pull requests to make this library even better.

## Coding Standards

To maintain the high quality and security of this library, please adhere to the following standards:

### General
- **Java Version**: Code must match Java 17 baseline.
- **Null Safety**: Use jSpecify annotations.
    - Packages are `@NullMarked` by default.
    - Explicitly annotate nullable parameters/returns with `@Nullable`.
- **Immutability**: Prefer immutable objects and `final` fields/variables where possible.
- **Dependencies**: Zero runtime dependencies policy (except for optional extensions like QR generation).

### Security
- **Memory Safety**: Use `SecureBytes` for handling raw secret key material.
- **Timing Attacks**: Use `TOTPEngine.constantTimeEquals()` for sensitive comparisons.
- **Input Validation**: strictly validate all public API inputs.

### Style
- **Indentation**: 4 spaces.
- **Formatting**: No empty lines at the beginning or end of methods.
- **Javadoc**: Required for all public classes and methods. 
- **Tests**: New features must include unit tests.

## Commit Message Standard

Follow **Conventional Commits** format for clear, consistent, and reviewable messages:

```
<type>(<scope>): <short summary>

<body>

<footer>
```

Only the **first line is mandatory**.

### Commit Types

| Type | Meaning | Example |
|-----|--------|--------|
| feat | New feature | `feat(TOTP)` |
| fix | Bug fix | `fix(ReplayGuard)` |
| docs | Documentation only | `docs(readme)` |
| style | Formatting, no logic change | `style(lint)` |
| refactor | Code refactor | `refactor(engine)` |
| perf | Performance improvement | `perf(cache)` |
| test | Adding or fixing tests | `test(security)` |
| build | Build system changes | `build(maven)` |
| ci | CI/CD changes | `ci(github)` |
| chore | Maintenance / tooling | `chore(deps)` |

### Examples

✅ **Good:**
```
feat(ReplayGuard): add distributed cache support

Add RedisReplayGuard implementation for distributed systems.
Maintains same API as InMemoryReplayGuard.

Fixes #123
```

❌ **Bad:**
```
fixed stuff
```

## How to Contribute

1.  **Fork the repository**
2.  **Create a feature branch** (`git checkout -b feature/amazing-feature`)
3.  **Commit your changes** with proper commit messages
4.  **Push to the branch** (`git push origin feature/amazing-feature`)
5.  **Open a Pull Request**

## Pull Request Checklist

- [ ] Tests pass (`mvn clean test`)
- [ ] Code coverage is maintained or improved
- [ ] Javadoc added/updated
- [ ] CHANGELOG.md updated (if applicable)
- [ ] Coding standards followed
- [ ] Commit messages follow the standard

## Reporting Bugs

Please include:
- Library version
- Java version
- Minimal reproduction code
- Expected vs actual behavior


