package com.pratiyush.totp.internal;

import java.util.Arrays;

/**
 * A wrapper for byte arrays containing sensitive data that ensures secure
 * clearing.
 * 
 * <p>
 * This class implements {@link AutoCloseable} to enable automatic memory
 * clearing
 * when used in try-with-resources blocks. This is critical for secrets and keys
 * that should not remain in memory longer than necessary.
 * </p>
 * 
 * <h2>Usage Example</h2>
 * 
 * <pre>{@code
 * try (SecureBytes secret = SecureBytes.wrap(secretBytes)) {
 *     // Use secret.getBytes() for operations
 *     byte[] hash = computeHmac(secret.getBytes(), data);
 * }
 * // secret is automatically cleared here
 * }</pre>
 * 
 * <h2>Security Notes</h2>
 * <ul>
 * <li>Always use try-with-resources to ensure clearing</li>
 * <li>After {@link #close()}, the bytes are zeroed</li>
 * <li>The {@link #toString()} method never reveals the data</li>
 * <li>Clone operations are not supported to prevent copies</li>
 * </ul>
 * 
 * <p>
 * <strong>Warning:</strong> This class provides best-effort memory clearing.
 * In Java, we cannot guarantee that the JVM hasn't made copies of the data.
 * For maximum security, consider using dedicated security hardware (HSM).
 * </p>
 */
public final class SecureBytes implements AutoCloseable {

    private final byte[] data;
    private volatile boolean cleared = false;

    /**
     * Creates a SecureBytes wrapper around the given array.
     * 
     * <p>
     * <strong>Important:</strong> This takes ownership of the array.
     * The caller should not retain or modify the original reference.
     * </p>
     * 
     * @param data the byte array to wrap (must not be null)
     * @throws NullPointerException if data is null
     */
    private SecureBytes(final byte[] data) {
        if (data == null) {
            throw new NullPointerException("Data must not be null");
        }
        this.data = data;
    }

    /**
     * Wraps an existing byte array.
     * 
     * <p>
     * <strong>Warning:</strong> The caller must not retain the original reference
     * as it would bypass the secure clearing mechanism.
     * </p>
     * 
     * @param data the byte array to wrap
     * @return new SecureBytes instance
     * @throws NullPointerException if data is null
     */
    public static SecureBytes wrap(final byte[] data) {
        return new SecureBytes(data);
    }

    /**
     * Creates a copy of the given byte array.
     * 
     * <p>
     * Use this when the original array must remain unchanged.
     * </p>
     * 
     * @param data the byte array to copy
     * @return new SecureBytes instance with a copy of the data
     * @throws NullPointerException if data is null
     */
    public static SecureBytes copyOf(final byte[] data) {
        return new SecureBytes(Arrays.copyOf(data, data.length));
    }

    /**
     * Creates a SecureBytes from a portion of the given array.
     * 
     * @param data   the source array
     * @param offset starting offset
     * @param length number of bytes to copy
     * @return new SecureBytes instance
     * @throws NullPointerException           if data is null
     * @throws ArrayIndexOutOfBoundsException if offset/length are invalid
     */
    public static SecureBytes copyOfRange(final byte[] data, final int offset, final int length) {
        byte[] copy = new byte[length];
        System.arraycopy(data, offset, copy, 0, length);
        return new SecureBytes(copy);
    }

    /**
     * Returns the underlying byte array.
     * 
     * <p>
     * <strong>Warning:</strong> Do not store references to this array.
     * It will be cleared when {@link #close()} is called.
     * </p>
     * 
     * @return the byte array
     * @throws IllegalStateException if already cleared
     */
    public byte[] getBytes() {
        if (cleared) {
            throw new IllegalStateException("SecureBytes has been cleared");
        }
        return data;
    }

    /**
     * Returns the length of the data.
     * 
     * @return length in bytes
     */
    public int length() {
        return data.length;
    }

    /**
     * Returns whether this instance has been cleared.
     * 
     * @return true if cleared
     */
    public boolean isCleared() {
        return cleared;
    }

    /**
     * Clears the underlying byte array by overwriting with zeros.
     * 
     * <p>
     * This method is idempotent - calling it multiple times is safe.
     * </p>
     */
    @Override
    public void close() {
        if (!cleared) {
            Arrays.fill(data, (byte) 0);
            cleared = true;
        }
    }

    /**
     * Returns a safe string representation that never reveals the data.
     * 
     * @return safe description string
     */
    @Override
    public String toString() {
        if (cleared) {
            return "SecureBytes[cleared]";
        }
        return String.format("SecureBytes[%d bytes]", data.length);
    }

    /**
     * Constant-time comparison of two byte arrays.
     * 
     * <p>
     * This method always compares all bytes to prevent timing attacks.
     * The comparison time is proportional to the minimum length of the arrays.
     * </p>
     * 
     * @param a first array
     * @param b second array
     * @return true if arrays are equal in length and content
     */
    public static boolean constantTimeEquals(final byte[] a, final byte[] b) {
        if (a == null || b == null) {
            return a == b;
        }

        if (a.length != b.length) {
            return false;
        }

        int result = 0;
        for (int i = 0; i < a.length; i++) {
            result |= a[i] ^ b[i];
        }
        return result == 0;
    }
}
