package io.github.pratiyush.totp;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.*;

/**
 * Tests for the InMemoryReplayGuard.
 */
@DisplayName("InMemoryReplayGuard Tests")
class InMemoryReplayGuardTest {

    private InMemoryReplayGuard guard;

    @BeforeEach
    void setUp() {
        guard = new InMemoryReplayGuard(Duration.ofSeconds(5));
    }

    @AfterEach
    void tearDown() {
        if (guard != null) {
            guard.close();
        }
    }

    @Nested
    @DisplayName("Basic Operations")
    class BasicOperations {

        @Test
        @DisplayName("Should mark code as used on first call")
        void shouldMarkAsUsedOnFirstCall() {
            boolean result = guard.markUsed("user:123456");

            assertThat(result).isTrue();
            assertThat(guard.size()).isEqualTo(1);
        }

        @Test
        @DisplayName("Should reject code on second call")
        void shouldRejectOnSecondCall() {
            guard.markUsed("user:123456");

            boolean result = guard.markUsed("user:123456");

            assertThat(result).isFalse();
        }

        @Test
        @DisplayName("Should allow different codes")
        void shouldAllowDifferentCodes() {
            boolean first = guard.markUsed("user:123456");
            boolean second = guard.markUsed("user:654321");

            assertThat(first).isTrue();
            assertThat(second).isTrue();
            assertThat(guard.size()).isEqualTo(2);
        }

        @Test
        @DisplayName("Should check if code was used")
        void shouldCheckIfUsed() {
            assertThat(guard.wasUsed("user:123456")).isFalse();

            guard.markUsed("user:123456");

            assertThat(guard.wasUsed("user:123456")).isTrue();
        }

        @Test
        @DisplayName("Should clear all codes")
        void shouldClearAllCodes() {
            guard.markUsed("user:123456");
            guard.markUsed("user:654321");

            guard.clear();

            assertThat(guard.size()).isEqualTo(0);
            assertThat(guard.markUsed("user:123456")).isTrue();
        }
    }

    @Nested
    @DisplayName("Null and Empty Handling")
    class NullAndEmptyHandling {

        @Test
        @DisplayName("Should reject null key")
        void shouldRejectNullKey() {
            boolean result = guard.markUsed(null);

            assertThat(result).isFalse();
        }

        @Test
        @DisplayName("Should reject empty key")
        void shouldRejectEmptyKey() {
            boolean result = guard.markUsed("");

            assertThat(result).isFalse();
        }

        @Test
        @DisplayName("Should return false for null wasUsed check")
        void shouldReturnFalseForNullCheck() {
            assertThat(guard.wasUsed(null)).isFalse();
        }
    }

    @Nested
    @DisplayName("Expiration")
    class Expiration {

        @Test
        @DisplayName("Should expire codes after retention period")
        void shouldExpireCodesAfterRetention() throws InterruptedException {
            // Use short retention for test
            guard.close();
            guard = new InMemoryReplayGuard(Duration.ofMillis(100));

            guard.markUsed("user:123456");
            assertThat(guard.wasUsed("user:123456")).isTrue();

            // Wait for expiration
            Thread.sleep(200);

            // Should be expired now
            assertThat(guard.wasUsed("user:123456")).isFalse();
            assertThat(guard.markUsed("user:123456")).isTrue(); // Can reuse
        }
    }

    @Nested
    @DisplayName("Concurrency")
    class Concurrency {

        @Test
        @DisplayName("Should be thread-safe")
        void shouldBeThreadSafe() throws InterruptedException {
            int threads = 10;
            int codesPerThread = 100;

            ExecutorService executor = Executors.newFixedThreadPool(threads);
            CountDownLatch latch = new CountDownLatch(threads);
            AtomicInteger successCount = new AtomicInteger(0);

            for (int t = 0; t < threads; t++) {
                final int threadId = t;
                executor.submit(() -> {
                    try {
                        for (int i = 0; i < codesPerThread; i++) {
                            String key = "user" + threadId + ":code" + i;
                            if (guard.markUsed(key)) {
                                successCount.incrementAndGet();
                            }
                        }
                    } finally {
                        latch.countDown();
                    }
                });
            }

            latch.await();
            executor.shutdown();

            // All codes should be unique, so all should succeed
            assertThat(successCount.get()).isEqualTo(threads * codesPerThread);
        }

        @Test
        @DisplayName("Should only allow one thread to mark same code")
        void shouldOnlyAllowOneThreadToMarkSameCode() throws InterruptedException {
            int threads = 100;

            ExecutorService executor = Executors.newFixedThreadPool(threads);
            CountDownLatch startLatch = new CountDownLatch(1);
            CountDownLatch doneLatch = new CountDownLatch(threads);
            AtomicInteger successCount = new AtomicInteger(0);

            String key = "shared:123456";

            for (int t = 0; t < threads; t++) {
                executor.submit(() -> {
                    try {
                        startLatch.await();
                        if (guard.markUsed(key)) {
                            successCount.incrementAndGet();
                        }
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    } finally {
                        doneLatch.countDown();
                    }
                });
            }

            startLatch.countDown(); // Start all threads
            doneLatch.await();
            executor.shutdown();

            // Only ONE thread should succeed
            assertThat(successCount.get()).isEqualTo(1);
        }
    }

    @Nested
    @DisplayName("Configuration")
    class Configuration {

        @Test
        @DisplayName("Should reject null retention")
        void shouldRejectNullRetention() {
            assertThatThrownBy(() -> new InMemoryReplayGuard(null))
                    .isInstanceOf(NullPointerException.class);
        }

        @Test
        @DisplayName("Should reject zero retention")
        void shouldRejectZeroRetention() {
            assertThatThrownBy(() -> new InMemoryReplayGuard(Duration.ZERO))
                    .isInstanceOf(IllegalArgumentException.class);
        }

        @Test
        @DisplayName("Should reject negative retention")
        void shouldRejectNegativeRetention() {
            assertThatThrownBy(() -> new InMemoryReplayGuard(Duration.ofSeconds(-1)))
                    .isInstanceOf(IllegalArgumentException.class);
        }

        @Test
        @DisplayName("Should create with default retention")
        void shouldCreateWithDefaultRetention() {
            InMemoryReplayGuard defaultGuard = InMemoryReplayGuard.withDefaultRetention();

            assertThat(defaultGuard.getRetention()).isEqualTo(Duration.ofMinutes(2));

            defaultGuard.close();
        }

        @Test
        @DisplayName("Should create for config")
        void shouldCreateForConfig() {
            TOTPConfig config = TOTPConfig.builder()
                    .periodSeconds(30)
                    .allowedDrift(2)
                    .build();

            InMemoryReplayGuard configGuard = InMemoryReplayGuard.forConfig(config);

            // Retention = 30 * (1 + 2*2) + 30 = 180 seconds = 3 minutes
            assertThat(configGuard.getRetention()).isEqualTo(Duration.ofSeconds(180));

            configGuard.close();
        }
    }

    @Nested
    @DisplayName("Lifecycle")
    class Lifecycle {

        @Test
        @DisplayName("Should throw after close")
        void shouldThrowAfterClose() {
            guard.close();

            assertThatThrownBy(() -> guard.markUsed("user:123456"))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("closed");
        }

        @Test
        @DisplayName("Close should be idempotent")
        void closeShouldBeIdempotent() {
            guard.close();
            guard.close(); // Should not throw
            guard.close(); // Should not throw
        }
    }
}
