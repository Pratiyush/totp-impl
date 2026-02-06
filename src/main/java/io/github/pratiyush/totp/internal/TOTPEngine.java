package io.github.pratiyush.totp.internal;

import io.github.pratiyush.totp.TOTPConfig;
import io.github.pratiyush.totp.TOTPException;

import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.time.Instant;

/**
 * Core TOTP engine implementing RFC 6238.
 * 
 * <p>
 * This class contains the actual TOTP algorithm implementation with
 * security-focused design:
 * </p>
 * <ul>
 * <li>Constant-time code comparison to prevent timing attacks</li>
 * <li>Configurable time drift tolerance</li>
 * <li>Support for all RFC-specified algorithms</li>
 * </ul>
 * 
 * <h2>Thread Safety</h2>
 * <p>
 * This class is thread-safe. The engine is stateless and all operations
 * are independent.
 * </p>
 * 
 * <h2>RFC Compliance</h2>
 * <p>
 * Implements TOTP as specified in RFC 6238, built on the HOTP algorithm
 * from RFC 4226.
 * </p>
 * 
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc6238">RFC 6238 -
 *      TOTP</a>
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc4226">RFC 4226 -
 *      HOTP</a>
 */
public final class TOTPEngine {

    /** Minimum secret length in bytes for security */
    public static final int MIN_SECRET_BYTES = 16;

    /** Power of 10 lookup for modulus calculation */
    private static final int[] POWERS_OF_TEN = {
            1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000
    };

    private TOTPEngine() {
        // Utility class
    }

    /**
     * Generates a TOTP code for the given secret and counter.
     * 
     * <p>
     * This is the core HOTP algorithm from RFC 4226, used by TOTP with
     * a time-based counter.
     * </p>
     * 
     * @param secret  the decoded secret key
     * @param counter the time-based counter (T = floor(time / period))
     * @param config  the TOTP configuration
     * @return the generated OTP code as a zero-padded string
     * @throws TOTPException if generation fails
     */
    public static String generateCode(final byte[] secret, final long counter, final TOTPConfig config)
            throws TOTPException {
        validateSecret(secret);

        // Convert counter to 8-byte big-endian array
        byte[] counterBytes = ByteBuffer.allocate(8).putLong(counter).array();

        // Compute HMAC
        byte[] hash = HMACProvider.compute(config.getAlgorithm(), secret, counterBytes);

        // Dynamic truncation per RFC 4226
        int offset = hash[hash.length - 1] & 0x0F;
        int binary = ((hash[offset] & 0x7F) << 24) |
                ((hash[offset + 1] & 0xFF) << 16) |
                ((hash[offset + 2] & 0xFF) << 8) |
                (hash[offset + 3] & 0xFF);

        // Compute OTP with modulus
        int otp = binary % POWERS_OF_TEN[config.getDigits()];

        // Format with leading zeros
        return String.format("%0" + config.getDigits() + "d", otp);
    }

    /**
     * Generates a TOTP code for the current time.
     * 
     * @param secret the decoded secret key
     * @param config the TOTP configuration
     * @param clock  the clock to use for time
     * @return the generated OTP code
     * @throws TOTPException if generation fails
     */
    public static String generateCode(final byte[] secret, final TOTPConfig config, final TOTPClock clock)
            throws TOTPException {
        long counter = clock.getCurrentCounter(config.getPeriodSeconds());
        return generateCode(secret, counter, config);
    }

    /**
     * Generates a TOTP code for a specific instant.
     * 
     * @param secret  the decoded secret key
     * @param instant the time to generate for
     * @param config  the TOTP configuration
     * @return the generated OTP code
     * @throws TOTPException if generation fails
     */
    public static String generateCodeAt(final byte[] secret, final Instant instant, final TOTPConfig config)
            throws TOTPException {
        long counter = TOTPClock.getCounterForInstant(instant, config.getPeriodSeconds());
        return generateCode(secret, counter, config);
    }

    /**
     * Verifies a TOTP code using constant-time comparison.
     * 
     * <p>
     * This method checks the provided code against codes generated for
     * time windows within the configured drift tolerance.
     * </p>
     * 
     * <b>Security</b>
     * <p>
     * Uses constant-time comparison to prevent timing attacks. The verification
     * time is independent of the code's correctness.
     * </p>
     * 
     * @param secret the decoded secret key
     * @param code   the code to verify
     * @param config the TOTP configuration
     * @param clock  the clock to use for time
     * @return true if the code is valid
     * @throws TOTPException if verification fails due to invalid input
     */
    public static boolean verifyCode(final byte[] secret, final String code,
            final TOTPConfig config, final TOTPClock clock)
            throws TOTPException {
        validateSecret(secret);

        if (!isValidCodeFormat(code, config.getDigits())) {
            return false;
        }

        long currentCounter = clock.getCurrentCounter(config.getPeriodSeconds());
        int drift = config.getAllowedDrift();

        // Check all windows in constant time
        boolean valid = false;
        for (int i = -drift; i <= drift; i++) {
            String expected = generateCode(secret, currentCounter + i, config);
            if (constantTimeEquals(code, expected)) {
                valid = true;
                // Don't return early - continue to prevent timing attacks
            }
        }
        return valid;
    }

    /**
     * Verifies a code and returns the matching counter offset if valid.
     * 
     * <p>
     * This variant is useful for replay attack prevention, as the offset
     * can be used to track which time window was used.
     * </p>
     * 
     * @param secret the decoded secret key
     * @param code   the code to verify
     * @param config the TOTP configuration
     * @param clock  the clock to use
     * @return the counter offset (-drift to +drift) if valid, or null if invalid
     * @throws TOTPException if verification fails due to invalid input
     */
    public static Integer verifyCodeWithOffset(final byte[] secret, final String code,
            final TOTPConfig config, final TOTPClock clock)
            throws TOTPException {
        validateSecret(secret);

        if (!isValidCodeFormat(code, config.getDigits())) {
            return null;
        }

        long currentCounter = clock.getCurrentCounter(config.getPeriodSeconds());
        int drift = config.getAllowedDrift();

        Integer matchingOffset = null;

        // Check all windows (iterate through all for timing consistency)
        for (int i = -drift; i <= drift; i++) {
            String expected = generateCode(secret, currentCounter + i, config);
            if (constantTimeEquals(code, expected)) {
                matchingOffset = i;
            }
        }
        return matchingOffset;
    }

    /**
     * Validates that the secret meets minimum security requirements.
     * 
     * @param secret the secret to validate
     * @throws TOTPException if the secret is invalid
     */
    public static void validateSecret(final byte[] secret) throws TOTPException {
        if (secret == null) {
            throw TOTPException.invalidSecret("Secret cannot be null");
        }
        if (secret.length < MIN_SECRET_BYTES) {
            throw TOTPException.invalidSecret(
                    "Secret must be at least " + MIN_SECRET_BYTES + " bytes, got " + secret.length);
        }
    }

    /**
     * Validates a Base32 encoded secret.
     * 
     * @param base32Secret the Base32 encoded secret
     * @throws TOTPException if invalid
     */
    public static void validateBase32Secret(final String base32Secret) throws TOTPException {
        if (base32Secret == null || base32Secret.isBlank()) {
            throw TOTPException.invalidSecret("Secret cannot be null or empty");
        }
        // Minimum 26 Base32 chars for 16 bytes (26 * 5 / 8 = 16.25)
        String cleaned = base32Secret.replaceAll("\\s", "").replaceAll("=+$", "");
        if (cleaned.length() < 26) {
            throw TOTPException.invalidSecret(
                    "Secret must be at least 26 Base32 characters for minimum security");
        }

        if (!Base32Codec.isValid(base32Secret)) {
            throw TOTPException.invalidSecret("Secret contains invalid Base32 characters");
        }
    }

    /**
     * Checks if a code string has valid format.
     * 
     * @param code           the code to check
     * @param expectedDigits expected number of digits
     * @return true if format is valid
     */
    public static boolean isValidCodeFormat(final String code, final int expectedDigits) {
        if (code == null || code.length() != expectedDigits) {
            return false;
        }

        for (int i = 0; i < code.length(); i++) {
            char c = code.charAt(i);
            if (c < '0' || c > '9') {
                return false;
            }
        }

        return true;
    }

    /**
     * Constant-time string comparison.
     * 
     * <p>
     * Uses {@link MessageDigest#isEqual} which provides constant-time
     * comparison to prevent timing attacks.
     * </p>
     * 
     * @param a first string
     * @param b second string
     * @return true if strings are equal
     */
    public static boolean constantTimeEquals(final String a, final String b) {
        if (a == null || b == null) {
            return a == b;
        }

        // Use MessageDigest.isEqual for constant-time comparison
        return MessageDigest.isEqual(a.getBytes(), b.getBytes());
    }
}
