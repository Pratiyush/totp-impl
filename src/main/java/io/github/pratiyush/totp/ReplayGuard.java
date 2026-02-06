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
