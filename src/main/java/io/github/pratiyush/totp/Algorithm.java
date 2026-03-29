/*
 * MIT License
 *
 * Copyright (c) 2026 Pratiyush Kumar Singh
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
package io.github.pratiyush.totp;

/**
 * Supported HMAC algorithms for TOTP generation.
 * 
 * <p>This enum provides type-safe algorithm selection, eliminating string typos
 * and ensuring only tested, secure algorithms are used.</p>
 * 
 * <h2>Algorithm Recommendations</h2>
 * <ul>
 *   <li>{@link #SHA1} - Default, widest compatibility (Google Authenticator)</li>
 *   <li>{@link #SHA256} - Recommended for new implementations</li>
 *   <li>{@link #SHA512} - Maximum security, larger key requirement</li>
 * </ul>
 * 
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc6238">RFC 6238 - TOTP</a>
 */
public enum Algorithm {
    
    /**
     * HMAC-SHA1 algorithm.
     * 
     * <p>Default algorithm with maximum compatibility. While SHA-1 has known
     * collision vulnerabilities, HMAC-SHA1 remains secure for TOTP use cases
     * as it operates in a keyed context.</p>
     * 
     * <p>Recommended key size: 20 bytes (160 bits)</p>
     */
    SHA1("HmacSHA1", 20),
    
    /**
     * HMAC-SHA256 algorithm.
     * 
     * <p>Recommended for new implementations. Provides better security margin
     * than SHA-1 while maintaining reasonable performance.</p>
     * 
     * <p>Recommended key size: 32 bytes (256 bits)</p>
     */
    SHA256("HmacSHA256", 32),
    
    /**
     * HMAC-SHA512 algorithm.
     * 
     * <p>Maximum security option. Use when security requirements demand the
     * highest margin of safety.</p>
     * 
     * <p>Recommended key size: 64 bytes (512 bits)</p>
     */
    SHA512("HmacSHA512", 64);
    
    private final String jcaName;
    private final int recommendedKeyBytes;
    
    Algorithm(final String jcaName, final int recommendedKeyBytes) {
        this.jcaName = jcaName;
        this.recommendedKeyBytes = recommendedKeyBytes;
    }
    
    /**
     * Returns the Java Cryptography Architecture (JCA) algorithm name.
     * 
     * @return JCA name suitable for use with {@link javax.crypto.Mac}
     */
    public String getJcaName() {
        return jcaName;
    }
    
    /**
     * Returns the recommended key size in bytes for this algorithm.
     * 
     * <p>Per RFC 6238, the key should be at least as long as the hash output.
     * Using shorter keys weakens security; longer keys provide no additional benefit.</p>
     * 
     * @return recommended key size in bytes
     */
    public int getRecommendedKeyBytes() {
        return recommendedKeyBytes;
    }
    
    /**
     * Returns the recommended secret length in Base32 characters.
     * 
     * <p>Base32 encodes 5 bits per character, so the character count is:
     * {@code ceil(keyBytes * 8 / 5)}</p>
     * 
     * @return recommended Base32 secret length
     */
    public int getRecommendedSecretLength() {
        return (int) Math.ceil(recommendedKeyBytes * 8.0 / 5.0);
    }
    
    /**
     * Returns the otpauth URI algorithm parameter value.
     * 
     * @return algorithm name for otpauth URI (e.g., "SHA256")
     */
    public String getOtpauthName() {
        return name();
    }
    
    /**
     * Parses an algorithm from its JCA name or enum name.
     * 
     * @param name the algorithm name (case-insensitive)
     * @return the matching algorithm
     * @throws IllegalArgumentException if no matching algorithm exists
     */
    public static Algorithm fromName(final String name) {
        if (name == null || name.isBlank()) {
            throw new IllegalArgumentException("Algorithm name cannot be null or empty");
        }
        
        final String normalized = name.toUpperCase().replace("HMAC", "").replace("-", "");
        
        for (Algorithm algo : values()) {
            if (algo.name().equals(normalized) || algo.jcaName.equalsIgnoreCase(name)) {
                return algo;
            }
        }
        
        throw new IllegalArgumentException("Unknown algorithm: " + name + 
            ". Supported: SHA1, SHA256, SHA512");
    }
}
