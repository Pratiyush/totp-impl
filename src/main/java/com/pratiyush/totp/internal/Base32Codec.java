package com.pratiyush.totp.internal;

import com.pratiyush.totp.TOTPException;

/**
 * RFC 4648 compliant Base32 encoder/decoder with zero external dependencies.
 * 
 * <p>
 * This implementation handles the standard Base32 alphabet (A-Z, 2-7) and
 * supports both padded and unpadded input/output.
 * </p>
 * 
 * <h2>Features</h2>
 * <ul>
 * <li>RFC 4648 compliant encoding/decoding</li>
 * <li>Case-insensitive decoding</li>
 * <li>Optional padding handling</li>
 * <li>Strict validation mode</li>
 * </ul>
 * 
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc4648">RFC 4648</a>
 */
public final class Base32Codec {

    /**
     * Standard Base32 alphabet per RFC 4648.
     */
    private static final String ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    /**
     * Lookup table for decoding (index = ASCII value - 'A' or '2').
     * -1 indicates invalid character.
     */
    private static final int[] DECODE_TABLE = new int[128];

    static {
        // Initialize all entries to -1 (invalid)
        for (int i = 0; i < DECODE_TABLE.length; i++) {
            DECODE_TABLE[i] = -1;
        }

        // Map uppercase letters A-Z to values 0-25
        for (int i = 0; i < 26; i++) {
            DECODE_TABLE['A' + i] = i;
            DECODE_TABLE['a' + i] = i; // Case-insensitive
        }

        // Map digits 2-7 to values 26-31
        for (int i = 0; i < 6; i++) {
            DECODE_TABLE['2' + i] = 26 + i;
        }
    }

    private Base32Codec() {
        // Utility class
    }

    /**
     * Encodes binary data to Base32 string without padding.
     * 
     * @param data the data to encode
     * @return Base32 encoded string (uppercase, no padding)
     * @throws NullPointerException if data is null
     */
    public static String encode(final byte[] data) {
        return encode(data, false);
    }

    /**
     * Encodes binary data to Base32 string.
     * 
     * @param data    the data to encode
     * @param padding whether to include padding characters
     * @return Base32 encoded string (uppercase)
     * @throws NullPointerException if data is null
     */
    public static String encode(final byte[] data, final boolean padding) {
        if (data == null) {
            throw new NullPointerException("Data must not be null");
        }

        if (data.length == 0) {
            return "";
        }

        // Calculate output length: ceil(inputBytes * 8 / 5)
        int outputLength = (data.length * 8 + 4) / 5;
        if (padding) {
            // Pad to multiple of 8
            outputLength = ((outputLength + 7) / 8) * 8;
        }

        StringBuilder result = new StringBuilder(outputLength);

        int buffer = 0;
        int bitsLeft = 0;

        for (byte b : data) {
            buffer = (buffer << 8) | (b & 0xFF);
            bitsLeft += 8;

            while (bitsLeft >= 5) {
                int index = (buffer >> (bitsLeft - 5)) & 0x1F;
                result.append(ALPHABET.charAt(index));
                bitsLeft -= 5;
            }
        }

        // Handle remaining bits
        if (bitsLeft > 0) {
            int index = (buffer << (5 - bitsLeft)) & 0x1F;
            result.append(ALPHABET.charAt(index));
        }

        // Add padding if requested
        if (padding) {
            while (result.length() % 8 != 0) {
                result.append('=');
            }
        }

        return result.toString();
    }

    /**
     * Decodes a Base32 string to binary data.
     * 
     * <p>
     * This method is lenient: it ignores whitespace, handles both
     * padded and unpadded input, and is case-insensitive.
     * </p>
     * 
     * @param encoded the Base32 string to decode
     * @return decoded binary data
     * @throws TOTPException if the string contains invalid characters
     */
    public static byte[] decode(final String encoded) throws TOTPException {
        if (encoded == null) {
            throw TOTPException.invalidSecret("Base32 string cannot be null");
        }

        // Remove whitespace and padding
        String cleaned = encoded.replaceAll("\\s", "").replaceAll("=+$", "");

        if (cleaned.isEmpty()) {
            return new byte[0];
        }

        // Validate and calculate output size
        int outputLength = cleaned.length() * 5 / 8;
        byte[] result = new byte[outputLength];

        int buffer = 0;
        int bitsLeft = 0;
        int resultIndex = 0;

        for (int i = 0; i < cleaned.length(); i++) {
            char c = cleaned.charAt(i);

            if (c >= DECODE_TABLE.length || DECODE_TABLE[c] < 0) {
                throw TOTPException.invalidSecret(
                        "Invalid Base32 character at position " + i + ": '" + c + "'");
            }

            buffer = (buffer << 5) | DECODE_TABLE[c];
            bitsLeft += 5;

            if (bitsLeft >= 8) {
                result[resultIndex++] = (byte) (buffer >> (bitsLeft - 8));
                bitsLeft -= 8;
            }
        }

        return result;
    }

    /**
     * Validates a Base32 string without decoding.
     * 
     * @param encoded the string to validate
     * @return true if the string is valid Base32
     */
    public static boolean isValid(final String encoded) {
        if (encoded == null || encoded.isEmpty()) {
            return false;
        }

        String cleaned = encoded.replaceAll("\\s", "").replaceAll("=+$", "");

        for (char c : cleaned.toCharArray()) {
            if (c >= DECODE_TABLE.length || DECODE_TABLE[c] < 0) {
                return false;
            }
        }

        return true;
    }

    /**
     * Returns the expected output size for a given input size.
     * 
     * @param inputBytes number of input bytes
     * @return number of Base32 characters (without padding)
     */
    public static int encodedLength(final int inputBytes) {
        return (inputBytes * 8 + 4) / 5;
    }

    /**
     * Returns the expected decoded size for a Base32 string length.
     * 
     * @param encodedLength number of Base32 characters (without padding)
     * @return number of decoded bytes
     */
    public static int decodedLength(final int encodedLength) {
        return encodedLength * 5 / 8;
    }
}
