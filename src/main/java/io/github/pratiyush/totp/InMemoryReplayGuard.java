package io.github.pratiyush.totp;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Thread-safe in-memory implementation of {@link ReplayGuard}.
 * 
 * <p>
 * This implementation stores used codes in a ConcurrentHashMap with
 * automatic expiration. Suitable for single-instance deployments.
 * </p>
 * 
 * <h2>Features</h2>
 * <ul>
 * <li>Thread-safe concurrent access</li>
 * <li>Automatic time-based expiration</li>
 * <li>Configurable retention period</li>
 * <li>Background cleanup thread</li>
 * </ul>
 * 
 * <h2>Limitations</h2>
 * <ul>
 * <li>Not suitable for clustered deployments (use Redis-backed
 * implementation)</li>
 * <li>Data lost on JVM restart</li>
 * </ul>
 * 
 * <h2>Usage Example</h2>
 * 
 * <pre>{@code
 * // Create with 2-minute retention (covers 30s period + drift)
 * ReplayGuard guard = new InMemoryReplayGuard(Duration.ofMinutes(2));
 * 
 * // Use with TOTP verification
 * TOTP totp = TOTP.builder().replayGuard(guard).build();
 * }</pre>
 * 
 * @see ReplayGuard
 */
public final class InMemoryReplayGuard implements ReplayGuard, AutoCloseable {

    private final Map<String, Instant> usedCodes = new ConcurrentHashMap<>();
    private final Duration retention;
    private final ScheduledExecutorService cleaner;
    private final AtomicBoolean closed = new AtomicBoolean(false);

    /**
     * Creates a new in-memory replay guard with the specified retention period.
     * 
     * <p>
     * The retention period should be at least: {@code period * (1 + 2 * drift)}
     * to ensure codes remain tracked for their entire validity window.
     * </p>
     * 
     * @param retention how long to track used codes
     * @throws NullPointerException     if retention is null
     * @throws IllegalArgumentException if retention is negative or zero
     */
    public InMemoryReplayGuard(final Duration retention) {
        if (retention == null) {
            throw new NullPointerException("Retention must not be null");
        }
        if (retention.isNegative() || retention.isZero()) {
            throw new IllegalArgumentException("Retention must be positive");
        }

        this.retention = retention;

        // Start background cleanup thread
        this.cleaner = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "totp-replay-guard-cleaner");
            t.setDaemon(true);
            return t;
        });

        // Run cleanup every retention period
        long cleanupIntervalMs = Math.max(retention.toMillis() / 2, 1000);
        cleaner.scheduleAtFixedRate(this::cleanup, cleanupIntervalMs, cleanupIntervalMs, TimeUnit.MILLISECONDS);
    }

    /**
     * Creates a replay guard with default retention of 2 minutes.
     * 
     * <p>
     * This default covers the standard 30-second period with drift of 1,
     * plus additional margin for clock skew.
     * </p>
     * 
     * @return new replay guard with default settings
     */
    public static InMemoryReplayGuard withDefaultRetention() {
        return new InMemoryReplayGuard(Duration.ofMinutes(2));
    }

    /**
     * Creates a replay guard configured for a specific TOTP configuration.
     * 
     * @param config the TOTP configuration
     * @return new replay guard with appropriate retention
     */
    public static InMemoryReplayGuard forConfig(final TOTPConfig config) {
        // Retention = period * (1 + 2 * drift) + 30s buffer
        int windows = 1 + 2 * config.getAllowedDrift();
        long retentionSeconds = (long) config.getPeriodSeconds() * windows + 30;
        return new InMemoryReplayGuard(Duration.ofSeconds(retentionSeconds));
    }

    @Override
    public boolean markUsed(final String key) {
        if (closed.get()) {
            throw new IllegalStateException("ReplayGuard has been closed");
        }

        if (key == null || key.isEmpty()) {
            return false;
        }

        Instant now = Instant.now();
        Instant previous = usedCodes.putIfAbsent(key, now);

        if (previous == null) {
            // First time this code is used
            return true;
        }

        // Check if previous entry has expired
        if (previous.plus(retention).isBefore(now)) {
            // Expired, try to replace
            if (usedCodes.replace(key, previous, now)) {
                return true;
            }
            // Another thread updated it, treat as replay
        }

        return false;
    }

    @Override
    public boolean wasUsed(final String key) {
        if (key == null || key.isEmpty()) {
            return false;
        }

        Instant timestamp = usedCodes.get(key);
        if (timestamp == null) {
            return false;
        }

        // Check if still within retention period
        return timestamp.plus(retention).isAfter(Instant.now());
    }

    @Override
    public void clear() {
        usedCodes.clear();
    }

    @Override
    public int size() {
        return usedCodes.size();
    }

    /**
     * Returns the configured retention period.
     * 
     * @return the retention duration
     */
    public Duration getRetention() {
        return retention;
    }

    /**
     * Removes expired entries from the map.
     */
    private void cleanup() {
        if (closed.get()) {
            return;
        }

        Instant cutoff = Instant.now().minus(retention);
        usedCodes.entrySet().removeIf(entry -> entry.getValue().isBefore(cutoff));
    }

    /**
     * Shuts down the background cleanup thread.
     */
    @Override
    public void close() {
        if (closed.compareAndSet(false, true)) {
            cleaner.shutdown();
            try {
                if (!cleaner.awaitTermination(5, TimeUnit.SECONDS)) {
                    cleaner.shutdownNow();
                }
            } catch (InterruptedException e) {
                cleaner.shutdownNow();
                Thread.currentThread().interrupt();
            }
        }
    }
}
