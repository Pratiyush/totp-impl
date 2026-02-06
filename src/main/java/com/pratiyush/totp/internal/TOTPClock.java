package com.pratiyush.totp.internal;

import java.time.Clock;
import java.time.Instant;
import java.util.Objects;

/**
 * Provides time for TOTP calculations with support for testing.
 * 
 * <p>
 * In production, use {@link #systemUTC()} which delegates to the system clock.
 * For testing, use {@link #fixed(Instant)} to control the time.
 * </p>
 * 
 * <h2>Usage Examples</h2>
 * 
 * <pre>{@code
 * // Production
 * TOTPClock clock = TOTPClock.systemUTC();
 * long counter = clock.getCurrentCounter(30);
 * 
 * // Testing
 * Instant testTime = Instant.parse("2009-02-13T23:31:30Z");
 * TOTPClock clock = TOTPClock.fixed(testTime);
 * }</pre>
 */
public final class TOTPClock {

    private final Clock clock;

    private TOTPClock(final Clock clock) {
        this.clock = Objects.requireNonNull(clock, "Clock must not be null");
    }

    /**
     * Creates a clock using the system UTC time.
     * 
     * @return system UTC clock
     */
    public static TOTPClock systemUTC() {
        return new TOTPClock(Clock.systemUTC());
    }

    /**
     * Creates a clock fixed at the specified instant.
     * 
     * <p>
     * Useful for testing with specific timestamps.
     * </p>
     * 
     * @param instant the fixed time
     * @return fixed clock
     */
    public static TOTPClock fixed(final Instant instant) {
        return new TOTPClock(Clock.fixed(instant, java.time.ZoneOffset.UTC));
    }

    /**
     * Creates a clock from a Java Clock instance.
     * 
     * @param clock the clock to use
     * @return TOTP clock wrapper
     */
    public static TOTPClock of(final Clock clock) {
        return new TOTPClock(clock);
    }

    /**
     * Returns the current time as an Instant.
     * 
     * @return current time
     */
    public Instant now() {
        return clock.instant();
    }

    /**
     * Returns the current Unix timestamp in seconds.
     * 
     * @return seconds since Unix epoch
     */
    public long currentTimeSeconds() {
        return clock.instant().getEpochSecond();
    }

    /**
     * Returns the current TOTP counter value.
     * 
     * <p>
     * The counter is calculated as: {@code floor(currentTime / periodSeconds)}
     * </p>
     * 
     * @param periodSeconds the TOTP period in seconds
     * @return current counter value
     */
    public long getCurrentCounter(final int periodSeconds) {
        return currentTimeSeconds() / periodSeconds;
    }

    /**
     * Returns the counter value for a specific timestamp.
     * 
     * @param instant       the timestamp
     * @param periodSeconds the TOTP period in seconds
     * @return counter value for that timestamp
     */
    public static long getCounterForInstant(final Instant instant, final int periodSeconds) {
        return instant.getEpochSecond() / periodSeconds;
    }

    /**
     * Returns the number of seconds remaining in the current period.
     * 
     * @param periodSeconds the TOTP period in seconds
     * @return seconds until the current code expires
     */
    public int getSecondsRemaining(final int periodSeconds) {
        return periodSeconds - (int) (currentTimeSeconds() % periodSeconds);
    }

    /**
     * Returns the underlying Java Clock.
     * 
     * @return the Java clock instance
     */
    public Clock getJavaClock() {
        return clock;
    }
}
