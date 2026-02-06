package io.github.pratiyush.totp;

import java.time.Duration;
import java.util.Objects;

/**
 * Immutable configuration for TOTP generation and verification.
 * 
 * <p>
 * This class uses the Builder pattern for flexible, validated construction.
 * All parameters are validated to ensure security constraints are met.
 * </p>
 * 
 * <h2>Default Configuration</h2>
 * <p>
 * The default configuration follows RFC 6238 recommendations and is compatible
 * with Google Authenticator:
 * </p>
 * <ul>
 * <li>Algorithm: SHA-1 (for compatibility)</li>
 * <li>Digits: 6</li>
 * <li>Period: 30 seconds</li>
 * <li>Allowed drift: 1 step (forward and backward)</li>
 * </ul>
 * 
 * <h2>Usage Examples</h2>
 * 
 * <pre>{@code
 * // Default configuration (Google Authenticator compatible)
 * TOTPConfig config = TOTPConfig.defaultConfig();
 * 
 * // Custom configuration
 * TOTPConfig config = TOTPConfig.builder()
 *         .algorithm(Algorithm.SHA256)
 *         .digits(8)
 *         .period(Duration.ofSeconds(30))
 *         .allowedDrift(1)
 *         .build();
 * }</pre>
 * 
 * @see Algorithm
 * @see TOTP
 */
public final class TOTPConfig {

    /** Minimum allowed period in seconds */
    public static final int MIN_PERIOD_SECONDS = 15;

    /** Maximum allowed period in seconds */
    public static final int MAX_PERIOD_SECONDS = 120;

    /** Minimum allowed digits */
    public static final int MIN_DIGITS = 6;

    /** Maximum allowed digits */
    public static final int MAX_DIGITS = 8;

    /** Maximum allowed drift steps */
    public static final int MAX_DRIFT_STEPS = 5;

    private final Algorithm algorithm;
    private final int digits;
    private final Duration period;
    private final int allowedDrift;

    private TOTPConfig(final Builder builder) {
        this.algorithm = builder.algorithm;
        this.digits = builder.digits;
        this.period = builder.period;
        this.allowedDrift = builder.allowedDrift;
    }

    /**
     * Returns the HMAC algorithm.
     * 
     * @return the algorithm, never null
     */
    public Algorithm getAlgorithm() {
        return algorithm;
    }

    /**
     * Returns the number of digits in generated codes.
     * 
     * @return digit count (6-8)
     */
    public int getDigits() {
        return digits;
    }

    /**
     * Returns the time period for code validity.
     * 
     * @return the period, never null
     */
    public Duration getPeriod() {
        return period;
    }

    /**
     * Returns the period in seconds.
     * 
     * @return period in seconds
     */
    public int getPeriodSeconds() {
        return (int) period.toSeconds();
    }

    /**
     * Returns the allowed drift steps for verification.
     * 
     * <p>
     * A drift of 1 means codes from 1 step before and 1 step after
     * the current time will be accepted.
     * </p>
     * 
     * @return allowed drift steps
     */
    public int getAllowedDrift() {
        return allowedDrift;
    }

    /**
     * Returns a builder with default values.
     * 
     * @return new builder instance
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Returns the default configuration (Google Authenticator compatible).
     * 
     * @return default configuration
     */
    public static TOTPConfig defaultConfig() {
        return builder().build();
    }

    /**
     * Returns a configuration optimized for SHA-256.
     * 
     * @return SHA-256 configuration
     */
    public static TOTPConfig sha256Config() {
        return builder().algorithm(Algorithm.SHA256).build();
    }

    /**
     * Returns a high-security configuration with SHA-512 and 8 digits.
     * 
     * @return high-security configuration
     */
    public static TOTPConfig highSecurityConfig() {
        return builder()
                .algorithm(Algorithm.SHA512)
                .digits(8)
                .build();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o)
            return true;
        if (o == null || getClass() != o.getClass())
            return false;
        TOTPConfig that = (TOTPConfig) o;
        return digits == that.digits &&
                allowedDrift == that.allowedDrift &&
                algorithm == that.algorithm &&
                Objects.equals(period, that.period);
    }

    @Override
    public int hashCode() {
        return Objects.hash(algorithm, digits, period, allowedDrift);
    }

    @Override
    public String toString() {
        return String.format("TOTPConfig[algorithm=%s, digits=%d, period=%ds, drift=%d]",
                algorithm, digits, period.toSeconds(), allowedDrift);
    }

    /**
     * Builder for creating {@link TOTPConfig} instances.
     * 
     * <p>
     * All setters validate their inputs immediately to fail fast on
     * configuration errors.
     * </p>
     */
    public static final class Builder {
        private Algorithm algorithm = Algorithm.SHA1;
        private int digits = 6;
        private Duration period = Duration.ofSeconds(30);
        private int allowedDrift = 1;

        private Builder() {
        }

        /**
         * Sets the HMAC algorithm.
         * 
         * @param algorithm the algorithm (must not be null)
         * @return this builder
         * @throws NullPointerException if algorithm is null
         */
        public Builder algorithm(final Algorithm algorithm) {
            this.algorithm = Objects.requireNonNull(algorithm, "Algorithm must not be null");
            return this;
        }

        /**
         * Sets the number of digits in generated codes.
         * 
         * @param digits digit count (must be 6-8)
         * @return this builder
         * @throws IllegalArgumentException if digits is out of range
         */
        public Builder digits(final int digits) {
            if (digits < MIN_DIGITS || digits > MAX_DIGITS) {
                throw new IllegalArgumentException(
                        String.format("Digits must be between %d and %d, got %d",
                                MIN_DIGITS, MAX_DIGITS, digits));
            }
            this.digits = digits;
            return this;
        }

        /**
         * Sets the time period for code validity.
         * 
         * @param period the period (must be 15-120 seconds)
         * @return this builder
         * @throws NullPointerException     if period is null
         * @throws IllegalArgumentException if period is out of range
         */
        public Builder period(final Duration period) {
            Objects.requireNonNull(period, "Period must not be null");
            long seconds = period.toSeconds();
            if (seconds < MIN_PERIOD_SECONDS || seconds > MAX_PERIOD_SECONDS) {
                throw new IllegalArgumentException(
                        String.format("Period must be between %d and %d seconds, got %d",
                                MIN_PERIOD_SECONDS, MAX_PERIOD_SECONDS, seconds));
            }
            this.period = period;
            return this;
        }

        /**
         * Sets the period in seconds.
         * 
         * @param seconds period in seconds (must be 15-120)
         * @return this builder
         * @throws IllegalArgumentException if seconds is out of range
         */
        public Builder periodSeconds(final int seconds) {
            return period(Duration.ofSeconds(seconds));
        }

        /**
         * Sets the allowed drift steps for verification.
         * 
         * <p>
         * A drift of 1 means codes from 1 step before and 1 step after
         * the current time will be accepted (3 codes total).
         * </p>
         * 
         * @param steps allowed drift steps (must be 0-5)
         * @return this builder
         * @throws IllegalArgumentException if steps is out of range
         */
        public Builder allowedDrift(final int steps) {
            if (steps < 0 || steps > MAX_DRIFT_STEPS) {
                throw new IllegalArgumentException(
                        String.format("Allowed drift must be between 0 and %d, got %d",
                                MAX_DRIFT_STEPS, steps));
            }
            this.allowedDrift = steps;
            return this;
        }

        /**
         * Builds the configuration.
         * 
         * @return immutable configuration instance
         */
        public TOTPConfig build() {
            return new TOTPConfig(this);
        }
    }
}
