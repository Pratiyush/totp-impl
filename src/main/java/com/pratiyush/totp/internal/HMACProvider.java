package com.pratiyush.totp.internal;

import com.pratiyush.totp.Algorithm;
import com.pratiyush.totp.TOTPException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * Secure HMAC computation for TOTP.
 * 
 * <p>
 * This utility class provides thread-safe HMAC calculation using the
 * Java Cryptography Architecture (JCA).
 * </p>
 * 
 * <h2>Thread Safety</h2>
 * <p>
 * This class is thread-safe. Each call creates a fresh Mac instance.
 * </p>
 * 
 * <h2>Security Notes</h2>
 * <ul>
 * <li>Uses standard JCA providers (no external crypto libraries)</li>
 * <li>Validates algorithm availability before use</li>
 * <li>Clear error messages for debugging (no secret leakage)</li>
 * </ul>
 */
public final class HMACProvider {

    private HMACProvider() {
        // Utility class
    }

    /**
     * Computes HMAC using the specified algorithm.
     * 
     * @param algorithm the HMAC algorithm
     * @param key       the secret key
     * @param data      the data to authenticate
     * @return the HMAC result
     * @throws TOTPException if HMAC computation fails
     */
    public static byte[] compute(final Algorithm algorithm, final byte[] key, final byte[] data)
            throws TOTPException {
        return compute(algorithm.getJcaName(), key, data);
    }

    /**
     * Computes HMAC using the specified algorithm name.
     * 
     * @param algorithmName the JCA algorithm name (e.g., "HmacSHA256")
     * @param key           the secret key
     * @param data          the data to authenticate
     * @return the HMAC result
     * @throws TOTPException if HMAC computation fails
     */
    public static byte[] compute(final String algorithmName, final byte[] key, final byte[] data)
            throws TOTPException {
        if (algorithmName == null || algorithmName.isEmpty()) {
            throw TOTPException.invalidConfig("Algorithm name cannot be null or empty");
        }
        if (key == null || key.length == 0) {
            throw TOTPException.invalidSecret("Key cannot be null or empty");
        }
        if (data == null) {
            throw TOTPException.invalidConfig("Data cannot be null");
        }

        try {
            Mac mac = Mac.getInstance(algorithmName);
            SecretKeySpec keySpec = new SecretKeySpec(key, algorithmName);
            mac.init(keySpec);
            return mac.doFinal(data);
        } catch (NoSuchAlgorithmException e) {
            throw TOTPException.invalidConfig(
                    "HMAC algorithm not available: " + algorithmName +
                            ". Ensure a compatible JCA provider is installed.");
        } catch (InvalidKeyException e) {
            throw TOTPException.invalidSecret("Invalid key for HMAC: " + e.getMessage());
        }
    }

    /**
     * Checks if an algorithm is available in the current JVM.
     * 
     * @param algorithm the algorithm to check
     * @return true if the algorithm is available
     */
    public static boolean isAlgorithmAvailable(final Algorithm algorithm) {
        return isAlgorithmAvailable(algorithm.getJcaName());
    }

    /**
     * Checks if an algorithm is available in the current JVM.
     * 
     * @param algorithmName the JCA algorithm name
     * @return true if the algorithm is available
     */
    public static boolean isAlgorithmAvailable(final String algorithmName) {
        try {
            Mac.getInstance(algorithmName);
            return true;
        } catch (NoSuchAlgorithmException e) {
            return false;
        }
    }
}
