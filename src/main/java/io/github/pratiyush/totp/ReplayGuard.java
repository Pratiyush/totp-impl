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
 * Interface for preventing TOTP code replay attacks.
 * 
 * <p>
 * A replay attack occurs when an attacker intercepts a valid TOTP code and
 * uses it again within its validity window. The ReplayGuard tracks used codes
 * to prevent this.
 * </p>
 * 
 * <h2>Usage Pattern</h2>
 * 
 * <pre>{@code
 * ReplayGuard guard = new InMemoryReplayGuard(Duration.ofMinutes(2));
 * 
 * // During verification
 * if (totp.verify(secret, code)) {
 *     String key = userId + ":" + code;
 *     if (guard.markUsed(key)) {
 *         // Code is valid and was not previously used
 *         authenticateUser();
 *     } else {
 *         // Code was already used - potential replay attack
 *         rejectAuthentication();
 *     }
 * }
 * }</pre>
 * 
 * <h2>Implementation Notes</h2>
 * <ul>
 * <li>Keys should include user identifier to prevent cross-user attacks</li>
 * <li>Entries should expire after code validity window passes</li>
 * <li>Thread-safe implementation required for production use</li>
 * </ul>
 * 
 * @see InMemoryReplayGuard
 */
public interface ReplayGuard {

    /**
     * Attempts to mark a code as used.
     * 
     * <p>
     * This method should be called after successful TOTP verification.
     * Returns true only if the code was not previously used.
     * </p>
     * 
     * @param key unique key combining user identifier and code
     * @return true if the code was successfully marked as used (first use),
     *         false if the code was already used
     */
    boolean markUsed(String key);

    /**
     * Checks if a code has been used without marking it.
     * 
     * @param key the key to check
     * @return true if the code was previously used
     */
    boolean wasUsed(String key);

    /**
     * Clears all tracked codes.
     * 
     * <p>
     * Use with caution - this resets replay protection.
     * </p>
     */
    void clear();

    /**
     * Returns the number of codes currently tracked.
     * 
     * @return count of tracked codes
     */
    int size();
}
