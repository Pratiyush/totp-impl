package com.pratiyush.totp;

import com.pratiyush.totp.internal.Base32Codec;

import org.jspecify.annotations.Nullable;

import java.security.SecureRandom;
import java.util.Objects;

/**
 * Secure generator for TOTP secrets.
 * 
 * <p>
 * This class uses {@link SecureRandom} for cryptographically strong
 * random number generation. Secrets are generated as raw bytes and
 * then encoded to Base32 for compatibility with authenticator apps.
 * </p>
 * 
 * <h2>Security Recommendations</h2>
 * <ul>
 * <li>Use at least 160 bits (20 bytes) of entropy for SHA-1</li>
 * <li>Use at least 256 bits (32 bytes) for SHA-256</li>
 * <li>Use at least 512 bits (64 bytes) for SHA-512</li>
 * </ul>
 * 
 * <h2>Usage Examples</h2>
 * 
 * <pre>{@code
 * // Generate secret for default SHA-1 (160 bits)
 * String secret = SecretGenerator.generate();
 * 
 * // Generate secret for specific algorithm
 * String secret = SecretGenerator.generate(Algorithm.SHA256);
 * 
 * // Generate with custom length
 * String secret = SecretGenerator.generate(64); // 64 bytes = 512 bits
 * }</pre>
 */
public final class SecretGenerator {

    /**
     * Thread-local SecureRandom for concurrent secret generation.
     */
    private static final ThreadLocal<SecureRandom> RANDOM = ThreadLocal.withInitial(() -> {
        SecureRandom random = new SecureRandom();
        // Force seeding
        random.nextBytes(new byte[1]);
        return random;
    });

    /** Default secret size in bytes (160 bits for SHA-1 compatibility) */
    public static final int DEFAULT_BYTES = 20;

    /** Minimum allowed secret size in bytes */
    public static final int MIN_BYTES = 16;

    private SecretGenerator() {
        // Utility class
    }

    /**
     * Generates a secret with default length (160 bits).
     * 
     * <p>
     * This is compatible with Google Authenticator and provides
     * adequate security for SHA-1 based TOTP.
     * </p>
     * 
     * @return Base32 encoded secret
     */
    public static String generate() {
        return generate(DEFAULT_BYTES);
    }

    /**
     * Generates a secret with appropriate length for the specified algorithm.
     * 
     * @param algorithm the algorithm that will use this secret
     * @return Base32 encoded secret
     * @throws NullPointerException if algorithm is null
     */
    public static String generate(final Algorithm algorithm) {
        Objects.requireNonNull(algorithm, "Algorithm must not be null");
        return generate(algorithm.getRecommendedKeyBytes());
    }

    /**
     * Generates a secret with the specified length in bytes.
     * 
     * @param lengthBytes number of random bytes (minimum 16)
     * @return Base32 encoded secret
     * @throws IllegalArgumentException if lengthBytes is less than 16
     */
    public static String generate(final int lengthBytes) {
        if (lengthBytes < MIN_BYTES) {
            throw new IllegalArgumentException(
                    "Secret length must be at least " + MIN_BYTES + " bytes, got " + lengthBytes);
        }

        byte[] bytes = generateBytes(lengthBytes);
        try {
            return Base32Codec.encode(bytes);
        } finally {
            // Clear the raw bytes
            java.util.Arrays.fill(bytes, (byte) 0);
        }
    }

    /**
     * Generates raw random bytes.
     * 
     * <p>
     * The caller is responsible for clearing these bytes after use.
     * </p>
     * 
     * @param length number of bytes to generate
     * @return random bytes
     */
    public static byte[] generateBytes(final int length) {
        if (length <= 0) {
            throw new IllegalArgumentException("Length must be positive");
        }

        byte[] bytes = new byte[length];
        RANDOM.get().nextBytes(bytes);
        return bytes;
    }

    /**
     * Validates that a secret meets minimum security requirements.
     * 
     * @param base32Secret the Base32 encoded secret to validate
     * @return true if the secret is valid
     */
    public static boolean isValid(final @Nullable String base32Secret) {
        if (base32Secret == null || base32Secret.isBlank()) {
            return false;
        }

        if (!Base32Codec.isValid(base32Secret)) {
            return false;
        }

        // Check minimum length (26 Base32 chars = 16 bytes minimum)
        String cleaned = base32Secret.replaceAll("\\s", "").replaceAll("=+$", "");
        return cleaned.length() >= 26;
    }

    /**
     * Returns the entropy in bits for a given Base32 secret length.
     * 
     * @param base32Length length of Base32 string (without padding)
     * @return entropy in bits
     */
    public static int entropyBits(final int base32Length) {
        return base32Length * 5;
    }

    /**
     * Returns the recommended secret length for a given algorithm.
     * 
     * @param algorithm the HMAC algorithm
     * @return recommended Base32 string length
     */
    public static int recommendedLength(final Algorithm algorithm) {
        return algorithm.getRecommendedSecretLength();
    }
}
