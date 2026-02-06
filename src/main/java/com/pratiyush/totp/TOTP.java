package com.pratiyush.totp;

import com.pratiyush.totp.internal.Base32Codec;
import com.pratiyush.totp.internal.SecureBytes;
import com.pratiyush.totp.internal.TOTPClock;
import com.pratiyush.totp.internal.TOTPEngine;

import org.jspecify.annotations.Nullable;

import java.time.Duration;
import java.time.Instant;
import java.util.Objects;

/**
 * Main entry point for TOTP operations.
 * 
 * <p>
 * This class provides a clean, secure API for generating and verifying
 * Time-based One-Time Passwords as specified in RFC 6238.
 * </p>
 * 
 * <h2>Quick Start</h2>
 * 
 * <pre>{@code
 * // Generate a secret for a new user
 * String secret = SecretGenerator.generate(Algorithm.SHA256);
 * 
 * // Create TOTP instance with default config
 * TOTP totp = TOTP.defaultInstance();
 * 
 * // Generate a code
 * String code = totp.generate(secret);
 * 
 * // Verify a code from user
 * boolean valid = totp.verify(secret, userProvidedCode);
 * }</pre>
 * 
 * <h2>Custom Configuration</h2>
 * 
 * <pre>{@code
 * TOTP totp = TOTP.builder()
 *         .config(TOTPConfig.sha256Config())
 *         .replayGuard(new InMemoryReplayGuard(Duration.ofMinutes(2)))
 *         .build();
 * }</pre>
 * 
 * <h2>Security Features</h2>
 * <ul>
 * <li><strong>Constant-time verification</strong>: Prevents timing attacks</li>
 * <li><strong>Replay protection</strong>: Optional guard against code
 * reuse</li>
 * <li><strong>Secure memory</strong>: Secrets cleared from memory after
 * use</li>
 * <li><strong>Input validation</strong>: Strict parameter checking</li>
 * </ul>
 * 
 * <h2>Thread Safety</h2>
 * <p>
 * Instances of this class are thread-safe when the optional ReplayGuard
 * is also thread-safe (which {@link InMemoryReplayGuard} is).
 * </p>
 * 
 * @author Pratiyush Kumar Singh
 * @version 1.0.0
 * @since 1.0.0
 * @see TOTPConfig
 * @see SecretGenerator
 * @see ReplayGuard
 */
public final class TOTP {

    private final TOTPConfig config;
    private final TOTPClock clock;
    private final @Nullable ReplayGuard replayGuard;

    /**
     * Creates a new TOTP instance with the specified configuration.
     * 
     * @param config      the configuration
     * @param clock       the clock for time
     * @param replayGuard optional replay guard (may be null)
     */
    private TOTP(final TOTPConfig config, final TOTPClock clock, final @Nullable ReplayGuard replayGuard) {
        this.config = Objects.requireNonNull(config, "Config must not be null");
        this.clock = Objects.requireNonNull(clock, "Clock must not be null");
        this.replayGuard = replayGuard; // May be null
    }

    /**
     * Returns a TOTP instance with default configuration.
     * 
     * <p>
     * Uses SHA-1 algorithm, 6 digits, 30-second period, and 1 step drift.
     * This is compatible with Google Authenticator.
     * </p>
     * 
     * @return default TOTP instance
     */
    public static TOTP defaultInstance() {
        return builder().build();
    }

    /**
     * Returns a builder for creating custom TOTP instances.
     * 
     * @return new builder
     */
    public static Builder builder() {
        return new Builder();
    }

    // ========================================================================
    // Generation Methods
    // ========================================================================

    /**
     * Generates a TOTP code for the current time.
     * 
     * @param base32Secret the Base32 encoded secret
     * @return the generated code
     * @throws TOTPException if generation fails
     */
    public String generate(final String base32Secret) throws TOTPException {
        TOTPEngine.validateBase32Secret(base32Secret);

        try (SecureBytes secret = SecureBytes.wrap(Base32Codec.decode(base32Secret))) {
            return TOTPEngine.generateCode(secret.getBytes(), config, clock);
        }
    }

    /**
     * Generates a TOTP code for a specific instant.
     * 
     * <p>
     * Useful for testing or generating future/past codes.
     * </p>
     * 
     * @param base32Secret the Base32 encoded secret
     * @param instant      the time to generate for
     * @return the generated code
     * @throws TOTPException if generation fails
     */
    public String generateAt(final String base32Secret, final Instant instant) throws TOTPException {
        Objects.requireNonNull(instant, "Instant must not be null");
        TOTPEngine.validateBase32Secret(base32Secret);

        try (SecureBytes secret = SecureBytes.wrap(Base32Codec.decode(base32Secret))) {
            return TOTPEngine.generateCodeAt(secret.getBytes(), instant, config);
        }
    }

    /**
     * Generates a TOTP code for a specific counter value.
     * 
     * <p>
     * Low-level method for advanced use cases.
     * </p>
     * 
     * @param base32Secret the Base32 encoded secret
     * @param counter      the TOTP counter value
     * @return the generated code
     * @throws TOTPException if generation fails
     */
    public String generateForCounter(final String base32Secret, final long counter) throws TOTPException {
        TOTPEngine.validateBase32Secret(base32Secret);

        try (SecureBytes secret = SecureBytes.wrap(Base32Codec.decode(base32Secret))) {
            return TOTPEngine.generateCode(secret.getBytes(), counter, config);
        }
    }

    // ========================================================================
    // Verification Methods
    // ========================================================================

    /**
     * Verifies a TOTP code.
     * 
     * <p>
     * This method uses constant-time comparison and optionally checks
     * the replay guard to prevent code reuse.
     * </p>
     * 
     * @param base32Secret the Base32 encoded secret
     * @param code         the code to verify
     * @return true if the code is valid
     * @throws TOTPException if verification fails due to invalid input
     */
    public boolean verify(final String base32Secret, final String code) throws TOTPException {
        return verify(base32Secret, code, null);
    }

    /**
     * Verifies a TOTP code with user-specific replay protection.
     * 
     * <p>
     * The userId is combined with the code to create a unique key for
     * replay protection. This prevents the same code from being used by
     * different users and tracks usage per-user.
     * </p>
     * 
     * @param base32Secret the Base32 encoded secret
     * @param code         the code to verify
     * @param userId       optional user identifier for replay protection
     * @return true if the code is valid and not replayed
     * @throws TOTPException if verification fails due to invalid input
     */
    public boolean verify(final String base32Secret, final String code, final @Nullable String userId)
            throws TOTPException {
        TOTPEngine.validateBase32Secret(base32Secret);

        if (!TOTPEngine.isValidCodeFormat(code, config.getDigits())) {
            return false;
        }

        boolean valid;
        try (SecureBytes secret = SecureBytes.wrap(Base32Codec.decode(base32Secret))) {
            valid = TOTPEngine.verifyCode(secret.getBytes(), code, config, clock);
        }

        if (!valid) {
            return false;
        }
        // Check replay guard if configured
        if (replayGuard != null) {
            String key = (userId != null ? userId + ":" : "") + code;
            if (!replayGuard.markUsed(key)) {
                // Code was already used
                return false;
            }
        }

        return true;
    }

    /**
     * Verifies a code and returns detailed result.
     * 
     * @param base32Secret the Base32 encoded secret
     * @param code         the code to verify
     * @return verification result with details
     * @throws TOTPException if verification fails due to invalid input
     */
    public VerificationResult verifyWithDetails(final String base32Secret, final String code)
            throws TOTPException {
        TOTPEngine.validateBase32Secret(base32Secret);

        if (!TOTPEngine.isValidCodeFormat(code, config.getDigits())) {
            return VerificationResult.invalid("Invalid code format");
        }

        Integer offset;
        try (SecureBytes secret = SecureBytes.wrap(Base32Codec.decode(base32Secret))) {
            offset = TOTPEngine.verifyCodeWithOffset(secret.getBytes(), code, config, clock);
        }

        if (offset == null) {
            return VerificationResult.invalid("Code does not match");
        }
        return VerificationResult.valid(offset);
    }

    // ========================================================================
    // Utility Methods
    // ========================================================================

    /**
     * Returns the current TOTP counter value.
     * 
     * @return current counter
     */
    public long getCurrentCounter() {
        return clock.getCurrentCounter(config.getPeriodSeconds());
    }

    /**
     * Returns seconds remaining until the current code expires.
     * 
     * @return seconds remaining
     */
    public int getSecondsRemaining() {
        return clock.getSecondsRemaining(config.getPeriodSeconds());
    }

    /**
     * Returns the configuration.
     * 
     * @return the TOTP configuration
     */
    public TOTPConfig getConfig() {
        return config;
    }

    /**
     * Returns the clock being used.
     * 
     * @return the TOTP clock
     */
    public TOTPClock getClock() {
        return clock;
    }

    // ========================================================================
    // Builder
    // ========================================================================

    /**
     * Builder for creating TOTP instances.
     */
    public static final class Builder {
        private TOTPConfig config = TOTPConfig.defaultConfig();
        private TOTPClock clock = TOTPClock.systemUTC();
        private @Nullable ReplayGuard replayGuard = null;

        private Builder() {
        }

        /**
         * Sets the TOTP configuration.
         * 
         * @param config the configuration
         * @return this builder
         */
        public Builder config(final TOTPConfig config) {
            this.config = Objects.requireNonNull(config, "Config must not be null");
            return this;
        }

        /**
         * Sets the algorithm.
         * 
         * @param algorithm the algorithm
         * @return this builder
         */
        public Builder algorithm(final Algorithm algorithm) {
            this.config = TOTPConfig.builder()
                    .algorithm(algorithm)
                    .digits(config.getDigits())
                    .period(config.getPeriod())
                    .allowedDrift(config.getAllowedDrift())
                    .build();
            return this;
        }

        /**
         * Sets the clock for time-based operations.
         * 
         * @param clock the clock to use
         * @return this builder
         */
        public Builder clock(final TOTPClock clock) {
            this.clock = Objects.requireNonNull(clock, "Clock must not be null");
            return this;
        }

        /**
         * Sets the replay guard.
         * 
         * @param replayGuard the replay guard (may be null to disable)
         * @return this builder
         */
        public Builder replayGuard(final @Nullable ReplayGuard replayGuard) {
            this.replayGuard = replayGuard;
            return this;
        }

        /**
         * Enables replay protection with an in-memory guard.
         * 
         * @param retention how long to track codes
         * @return this builder
         */
        public Builder withReplayProtection(final Duration retention) {
            this.replayGuard = new InMemoryReplayGuard(retention);
            return this;
        }

        /**
         * Enables replay protection with default retention.
         * 
         * @return this builder
         */
        public Builder withReplayProtection() {
            this.replayGuard = InMemoryReplayGuard.forConfig(config);
            return this;
        }

        /**
         * Builds the TOTP instance.
         * 
         * @return configured TOTP instance
         */
        public TOTP build() {
            return new TOTP(config, clock, replayGuard);
        }
    }

    // ========================================================================
    // Verification Result
    // ========================================================================

    /**
     * Result of a TOTP verification with additional details.
     */
    public static final class VerificationResult {
        private final boolean valid;
        private final Integer timeOffset;
        private final String message;

        private VerificationResult(boolean valid, Integer timeOffset, String message) {
            this.valid = valid;
            this.timeOffset = timeOffset;
            this.message = message;
        }

        static VerificationResult valid(int offset) {
            return new VerificationResult(true, offset, "Valid");
        }

        static VerificationResult invalid(String message) {
            return new VerificationResult(false, null, message);
        }

        /**
         * Returns whether the code was valid.
         */
        public boolean isValid() {
            return valid;
        }

        /**
         * Returns the time offset of the matching code.
         * 
         * <p>
         * 0 means the current time window, negative values mean past
         * windows, positive values mean future windows.
         * </p>
         * 
         * @return time offset, or null if invalid
         */
        public Integer getTimeOffset() {
            return timeOffset;
        }

        /**
         * Returns a human-readable message.
         */
        public String getMessage() {
            return message;
        }

        @Override
        public String toString() {
            if (valid) {
                return String.format("VerificationResult[valid, offset=%d]", timeOffset);
            }
            return String.format("VerificationResult[invalid: %s]", message);
        }
    }
}
