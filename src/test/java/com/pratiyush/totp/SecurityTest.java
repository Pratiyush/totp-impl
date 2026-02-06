package com.pratiyush.totp;

import com.pratiyush.totp.internal.SecureBytes;
import com.pratiyush.totp.internal.TOTPEngine;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import static org.assertj.core.api.Assertions.*;

/**
 * Security-focused tests for the TOTP library.
 * 
 * These tests verify security properties like timing attack resistance,
 * memory clearing, and entropy quality.
 */
@DisplayName("Security Tests")
class SecurityTest {

    @Nested
    @DisplayName("Timing Attack Resistance")
    class TimingAttackResistance {

        @Test
        @DisplayName("Constant-time comparison should have consistent timing")
        void constantTimeComparisonShouldHaveConsistentTiming() {
            String base = "123456";
            String matchingFirst = "100000"; // Differs at 2nd char
            String matchingLast = "123450"; // Differs at last char

            // Warm up
            for (int i = 0; i < 1000; i++) {
                TOTPEngine.constantTimeEquals(base, matchingFirst);
                TOTPEngine.constantTimeEquals(base, matchingLast);
            }

            // Measure timing variance
            int iterations = 10000;
            long[] firstCharTimes = new long[iterations];
            long[] lastCharTimes = new long[iterations];

            for (int i = 0; i < iterations; i++) {
                long start1 = System.nanoTime();
                TOTPEngine.constantTimeEquals(base, matchingFirst);
                firstCharTimes[i] = System.nanoTime() - start1;

                long start2 = System.nanoTime();
                TOTPEngine.constantTimeEquals(base, matchingLast);
                lastCharTimes[i] = System.nanoTime() - start2;
            }

            // Calculate averages
            double avgFirst = Arrays.stream(firstCharTimes).average().orElse(0);
            double avgLast = Arrays.stream(lastCharTimes).average().orElse(0);

            // The times should be similar (within 50% of each other)
            // This is a probabilistic test - may occasionally fail due to JIT/GC
            double ratio = avgFirst / avgLast;
            assertThat(ratio)
                    .as("Timing ratio should be close to 1.0 (was %.2f)", ratio)
                    .isBetween(0.5, 2.0);
        }

        @Test
        @DisplayName("Verification should take similar time for valid and invalid codes")
        void verificationShouldTakeSimilarTime() throws TOTPException {
            String secret = SecretGenerator.generate();
            TOTP totp = TOTP.defaultInstance();
            String validCode = totp.generate(secret);
            String invalidCode = "000000";

            // Warm up
            for (int i = 0; i < 100; i++) {
                totp.verify(secret, validCode);
                totp.verify(secret, invalidCode);
            }

            // Measure
            int iterations = 1000;
            long[] validTimes = new long[iterations];
            long[] invalidTimes = new long[iterations];

            for (int i = 0; i < iterations; i++) {
                long start1 = System.nanoTime();
                totp.verify(secret, validCode);
                validTimes[i] = System.nanoTime() - start1;

                long start2 = System.nanoTime();
                totp.verify(secret, invalidCode);
                invalidTimes[i] = System.nanoTime() - start2;
            }

            double avgValid = Arrays.stream(validTimes).average().orElse(0);
            double avgInvalid = Arrays.stream(invalidTimes).average().orElse(0);

            // Times should be within 3x of each other
            double ratio = avgValid / avgInvalid;
            assertThat(ratio)
                    .as("Timing ratio should be close to 1.0 (was %.2f)", ratio)
                    .isBetween(0.33, 3.0);
        }
    }

    @Nested
    @DisplayName("Memory Security")
    class MemorySecurity {

        @Test
        @DisplayName("SecureBytes should clear on close")
        void secureByteShouldClearOnClose() {
            byte[] data = { 1, 2, 3, 4, 5, 6, 7, 8 };
            SecureBytes secure = SecureBytes.wrap(data);

            // Verify data is accessible
            assertThat(secure.getBytes()).containsExactly(1, 2, 3, 4, 5, 6, 7, 8);

            // Close and verify cleared
            secure.close();

            assertThat(secure.isCleared()).isTrue();
            assertThat(data).containsExactly(0, 0, 0, 0, 0, 0, 0, 0);
        }

        @Test
        @DisplayName("SecureBytes should prevent access after close")
        void secureByteShouldPreventAccessAfterClose() {
            SecureBytes secure = SecureBytes.copyOf(new byte[] { 1, 2, 3 });
            secure.close();

            assertThatThrownBy(secure::getBytes)
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("cleared");
        }

        @Test
        @DisplayName("SecureBytes try-with-resources should clear")
        void tryWithResourcesShouldClear() {
            byte[] data = { 1, 2, 3, 4 };

            try (SecureBytes secure = SecureBytes.wrap(data)) {
                assertThat(secure.getBytes()).containsExactly(1, 2, 3, 4);
            }

            // After try block, should be cleared
            assertThat(data).containsExactly(0, 0, 0, 0);
        }

        @Test
        @DisplayName("SecureBytes toString should not reveal data")
        void toStringShouldNotRevealData() {
            SecureBytes secure = SecureBytes.copyOf(new byte[] { (byte) 0xDE, (byte) 0xAD, (byte) 0xBE, (byte) 0xEF });

            String toString = secure.toString();

            assertThat(toString)
                    .doesNotContain("DE")
                    .doesNotContain("AD")
                    .doesNotContain("BE")
                    .doesNotContain("EF")
                    .doesNotContain("dead")
                    .doesNotContain("beef");
        }
    }

    @Nested
    @DisplayName("Secret Generation Quality")
    class SecretGenerationQuality {

        @RepeatedTest(5)
        @DisplayName("Generated secrets should be unique")
        void generatedSecretsShouldBeUnique() {
            Set<String> secrets = new HashSet<>();

            for (int i = 0; i < 1000; i++) {
                String secret = SecretGenerator.generate();
                boolean added = secrets.add(secret);
                assertThat(added)
                        .as("Secret %d should be unique", i)
                        .isTrue();
            }
        }

        @Test
        @DisplayName("Generated secrets should have sufficient length")
        void generatedSecretsShouldHaveSufficientLength() {
            String sha1Secret = SecretGenerator.generate(Algorithm.SHA1);
            String sha256Secret = SecretGenerator.generate(Algorithm.SHA256);
            String sha512Secret = SecretGenerator.generate(Algorithm.SHA512);

            // SHA1: 20 bytes = 32 Base32 chars
            assertThat(sha1Secret.length()).isGreaterThanOrEqualTo(32);

            // SHA256: 32 bytes = 52 Base32 chars
            assertThat(sha256Secret.length()).isGreaterThanOrEqualTo(52);

            // SHA512: 64 bytes = 103 Base32 chars
            assertThat(sha512Secret.length()).isGreaterThanOrEqualTo(103);
        }

        @Test
        @DisplayName("Generated secrets should pass validation")
        void generatedSecretsShouldPassValidation() {
            for (int i = 0; i < 100; i++) {
                String secret = SecretGenerator.generate();
                assertThat(SecretGenerator.isValid(secret))
                        .as("Generated secret should be valid")
                        .isTrue();
            }
        }

        @Test
        @DisplayName("Should reject too-short secret generation")
        void shouldRejectTooShortSecretGeneration() {
            assertThatThrownBy(() -> SecretGenerator.generate(15))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("at least 16");
        }
    }

    @Nested
    @DisplayName("Input Validation")
    class InputValidation {

        @Test
        @DisplayName("Should reject secrets with insufficient entropy")
        void shouldRejectLowEntropySecrets() {
            TOTP totp = TOTP.defaultInstance();

            // 16 chars = 80 bits, below our 26 char (130 bit) minimum
            assertThatThrownBy(() -> totp.generate("AAAAAAAAAAAAAAAA"))
                    .isInstanceOf(TOTPException.class)
                    .hasMessageContaining("at least 26");
        }

        @Test
        @DisplayName("Should reject invalid Base32 in secrets")
        void shouldRejectInvalidBase32InSecrets() {
            TOTP totp = TOTP.defaultInstance();

            // Contains invalid characters (0, 1, 8, 9)
            assertThatThrownBy(() -> totp.generate("JBSWY3DPEHPK3PXP01890189AABB"))
                    .isInstanceOf(TOTPException.class)
                    .hasMessageContaining("invalid");
        }
    }

    @Nested
    @DisplayName("Exception Safety")
    class ExceptionSafety {

        @Test
        @DisplayName("Exception messages should not contain secrets")
        void exceptionMessagesShouldNotContainSecrets() {
            TOTP totp = TOTP.defaultInstance();

            // This secret is invalid (contains 0)
            String invalidSecret = "JBSWY3DPEHPK3PXP0000000000AB";

            try {
                totp.generate(invalidSecret);
                fail("Should have thrown exception");
            } catch (TOTPException e) {
                String message = e.getMessage();

                // Should not contain the actual secret value
                assertThat(message)
                        .doesNotContain("JBSWY3DPEHPK3PXP")
                        .doesNotContain(invalidSecret);
            }
        }

        @Test
        @DisplayName("Error codes should be present")
        void errorCodesShouldBePresent() {
            TOTPException ex = TOTPException.invalidSecret("test");

            assertThat(ex.getErrorCode())
                    .isNotNull()
                    .isEqualTo(TOTPException.ErrorCode.INVALID_SECRET);
        }
    }
}
