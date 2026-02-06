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

## How to Contribute

1.  **Fork the repository**
2.  **Create a feature branch** (`git checkout -b feature/amazing-feature`)
3.  **Commit your changes** (`git commit -m 'Add some amazing feature'`)
4.  **Push to the branch** (`git push origin feature/amazing-feature`)
5.  **Open a Pull Request**

## Pull Request Checklist

- [ ] Tests pass (`mvn clean test`)
- [ ] Code coverage is maintained or improved
- [ ] Javadoc added/updated
- [ ] CHANGELOG.md updated (if applicable)
- [ ] Coding standards followed

## Reporting Bugs

Please include:
- Library version
- Java version
- Minimal reproduction code
- Expected vs actual behavior
