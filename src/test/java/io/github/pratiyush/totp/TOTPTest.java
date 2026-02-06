package io.github.pratiyush.totp;

import io.github.pratiyush.totp.internal.TOTPClock;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.time.Duration;
import java.time.Instant;

import static org.assertj.core.api.Assertions.*;

/**
 * Comprehensive tests for TOTP generation and verification.
 */
@DisplayName("TOTP Tests")
class TOTPTest {

    // Test secret: 32 chars = 160 bits, sufficient for all algorithms
    private static final String TEST_SECRET = "JBSWY3DPEHPK3PXP7OZXGZ3DPEHPK3PX";

    @Nested
    @DisplayName("Basic Generation")
    class Generation {

        @Test
        @DisplayName("Should generate 6-digit code with default config")
        void shouldGenerate6DigitCode() throws TOTPException {
            final TOTP totp = TOTP.defaultInstance();
            final String code = totp.generate(TEST_SECRET);

            assertThat(code)
                    .hasSize(6)
                    .containsOnlyDigits();
        }

        @Test
        @DisplayName("Should generate 8-digit code when configured")
        void shouldGenerate8DigitCode() throws TOTPException {
            final TOTP totp = TOTP.builder()
                    .config(TOTPConfig.builder().digits(8).build())
                    .build();

            final String code = totp.generate(TEST_SECRET);

            assertThat(code)
                    .hasSize(8)
                    .containsOnlyDigits();
        }

        @Test
        @DisplayName("Should pad codes with leading zeros")
        void shouldPadWithLeadingZeros() throws TOTPException {
            // Use a fixed time that generates a code with leading zeros
            // Counter = 0 with this secret gives a code starting with 0
            final TOTPClock fixedClock = TOTPClock.fixed(Instant.ofEpochSecond(0));
            final TOTP totp = TOTP.builder().clock(fixedClock).build();
            final String code = totp.generate(TEST_SECRET);

            assertThat(code).hasSize(6);
        }

        @Test
        @DisplayName("Should generate consistent codes for same time")
        void shouldGenerateConsistentCodes() throws TOTPException {
            Instant fixedTime = Instant.parse("2024-01-01T12:00:00Z");
            TOTPClock clock = TOTPClock.fixed(fixedTime);
            TOTP totp = TOTP.builder().clock(clock).build();

            String code1 = totp.generate(TEST_SECRET);
            String code2 = totp.generate(TEST_SECRET);

            assertThat(code1).isEqualTo(code2);
        }

        @Test
        @DisplayName("Should generate different codes for different secrets")
        void shouldGenerateDifferentCodesForDifferentSecrets() throws TOTPException {
            TOTP totp = TOTP.defaultInstance();

            String secret1 = SecretGenerator.generate();
            String secret2 = SecretGenerator.generate();

            String code1 = totp.generate(secret1);
            String code2 = totp.generate(secret2);

            assertThat(code1).isNotEqualTo(code2);
        }
    }

    @Nested
    @DisplayName("Verification")
    class Verification {

        @Test
        @DisplayName("Should verify correct code")
        void shouldVerifyCorrectCode() throws TOTPException {
            TOTP totp = TOTP.defaultInstance();
            String code = totp.generate(TEST_SECRET);

            boolean valid = totp.verify(TEST_SECRET, code);

            assertThat(valid).isTrue();
        }

        @Test
        @DisplayName("Should reject incorrect code")
        void shouldRejectIncorrectCode() throws TOTPException {
            TOTP totp = TOTP.defaultInstance();

            boolean valid = totp.verify(TEST_SECRET, "000000");

            assertThat(valid).isFalse();
        }

        @Test
        @DisplayName("Should accept code within drift window")
        void shouldAcceptCodeWithinDriftWindow() throws TOTPException {
            Instant now = Instant.now();

            // Generate code at current time
            TOTP generator = TOTP.builder()
                    .clock(TOTPClock.fixed(now))
                    .build();
            String code = generator.generate(TEST_SECRET);

            // Verify at 1 step in the future
            TOTP verifier = TOTP.builder()
                    .clock(TOTPClock.fixed(now.plusSeconds(30)))
                    .config(TOTPConfig.builder().allowedDrift(1).build())
                    .build();

            boolean valid = verifier.verify(TEST_SECRET, code);

            assertThat(valid).isTrue();
        }

        @Test
        @DisplayName("Should reject code outside drift window")
        void shouldRejectCodeOutsideDriftWindow() throws TOTPException {
            Instant now = Instant.now();

            // Generate code at current time
            TOTP generator = TOTP.builder()
                    .clock(TOTPClock.fixed(now))
                    .build();
            String code = generator.generate(TEST_SECRET);

            // Verify at 3 steps in the future (outside drift of 1)
            TOTP verifier = TOTP.builder()
                    .clock(TOTPClock.fixed(now.plusSeconds(90)))
                    .config(TOTPConfig.builder().allowedDrift(1).build())
                    .build();

            boolean valid = verifier.verify(TEST_SECRET, code);

            assertThat(valid).isFalse();
        }

        @ParameterizedTest
        @DisplayName("Should reject invalid code formats")
        @ValueSource(strings = { "", "12345", "1234567", "abcdef", "12345a", " 123456" })
        void shouldRejectInvalidFormats(String code) throws TOTPException {
            TOTP totp = TOTP.defaultInstance();

            boolean valid = totp.verify(TEST_SECRET, code);

            assertThat(valid).isFalse();
        }

        @Test
        @DisplayName("Should reject null code")
        void shouldRejectNullCode() throws TOTPException {
            TOTP totp = TOTP.defaultInstance();

            boolean valid = totp.verify(TEST_SECRET, null);

            assertThat(valid).isFalse();
        }
    }

    @Nested
    @DisplayName("Verification With Details")
    class VerificationWithDetails {

        @Test
        @DisplayName("Should return valid result with offset 0 for current code")
        void shouldReturnOffset0ForCurrentCode() throws TOTPException {
            Instant now = Instant.now();
            TOTPClock clock = TOTPClock.fixed(now);
            TOTP totp = TOTP.builder().clock(clock).build();

            String code = totp.generate(TEST_SECRET);
            TOTP.VerificationResult result = totp.verifyWithDetails(TEST_SECRET, code);

            assertThat(result.isValid()).isTrue();
            assertThat(result.getTimeOffset()).isEqualTo(0);
        }

        @Test
        @DisplayName("Should return correct offset for past code")
        void shouldReturnNegativeOffsetForPastCode() throws TOTPException {
            Instant now = Instant.now();

            // Generate at T-30 seconds
            TOTP generator = TOTP.builder()
                    .clock(TOTPClock.fixed(now.minusSeconds(30)))
                    .build();
            String code = generator.generate(TEST_SECRET);

            // Verify at T
            TOTP verifier = TOTP.builder()
                    .clock(TOTPClock.fixed(now))
                    .config(TOTPConfig.builder().allowedDrift(1).build())
                    .build();

            TOTP.VerificationResult result = verifier.verifyWithDetails(TEST_SECRET, code);

            assertThat(result.isValid()).isTrue();
            assertThat(result.getTimeOffset()).isEqualTo(-1);
        }
    }

    @Nested
    @DisplayName("Algorithm Support")
    class AlgorithmSupport {

        @ParameterizedTest
        @DisplayName("Should work with all algorithms")
        @CsvSource({
                "SHA1, 6",
                "SHA256, 6",
                "SHA512, 6",
                "SHA1, 8",
                "SHA256, 8"
        })
        void shouldWorkWithAllAlgorithms(Algorithm algorithm, int digits) throws TOTPException {
            TOTPConfig config = TOTPConfig.builder()
                    .algorithm(algorithm)
                    .digits(digits)
                    .build();

            TOTP totp = TOTP.builder().config(config).build();
            String secret = SecretGenerator.generate(algorithm);

            String code = totp.generate(secret);
            boolean valid = totp.verify(secret, code);

            assertThat(code).hasSize(digits);
            assertThat(valid).isTrue();
        }
    }

    @Nested
    @DisplayName("Replay Protection")
    class ReplayProtection {

        @Test
        @DisplayName("Should prevent code reuse with replay guard")
        void shouldPreventCodeReuse() throws TOTPException {
            TOTP totp = TOTP.builder()
                    .withReplayProtection(Duration.ofMinutes(2))
                    .build();

            String code = totp.generate(TEST_SECRET);

            // First use should succeed
            boolean firstUse = totp.verify(TEST_SECRET, code, "user1");
            assertThat(firstUse).isTrue();

            // Second use should fail
            boolean secondUse = totp.verify(TEST_SECRET, code, "user1");
            assertThat(secondUse).isFalse();
        }

        @Test
        @DisplayName("Should allow same code for different users")
        void shouldAllowSameCodeForDifferentUsers() throws TOTPException {
            Instant now = Instant.now();
            TOTPClock clock = TOTPClock.fixed(now);
            TOTP totp = TOTP.builder()
                    .clock(clock)
                    .withReplayProtection(Duration.ofMinutes(2))
                    .build();

            String code = totp.generate(TEST_SECRET);

            boolean user1 = totp.verify(TEST_SECRET, code, "user1");
            boolean user2 = totp.verify(TEST_SECRET, code, "user2");

            assertThat(user1).isTrue();
            assertThat(user2).isTrue();
        }
    }

    @Nested
    @DisplayName("Secret Validation")
    class SecretValidation {

        @Test
        @DisplayName("Should reject null secret")
        void shouldRejectNullSecret() {
            TOTP totp = TOTP.defaultInstance();

            assertThatThrownBy(() -> totp.generate(null))
                    .isInstanceOf(TOTPException.class)
                    .hasMessageContaining("null or empty");
        }

        @Test
        @DisplayName("Should reject empty secret")
        void shouldRejectEmptySecret() {
            TOTP totp = TOTP.defaultInstance();

            assertThatThrownBy(() -> totp.generate(""))
                    .isInstanceOf(TOTPException.class)
                    .hasMessageContaining("null or empty");
        }

        @Test
        @DisplayName("Should reject too short secret")
        void shouldRejectTooShortSecret() {
            TOTP totp = TOTP.defaultInstance();

            assertThatThrownBy(() -> totp.generate("JBSWY3DPEHPK3PXP")) // 16 chars
                    .isInstanceOf(TOTPException.class)
                    .hasMessageContaining("at least 26");
        }

        @Test
        @DisplayName("Should reject invalid Base32 characters")
        void shouldRejectInvalidBase32() {
            TOTP totp = TOTP.defaultInstance();

            assertThatThrownBy(() -> totp.generate("JBSWY3DPEHPK3PXP0189AABBCCD"))
                    .isInstanceOf(TOTPException.class)
                    .hasMessageContaining("invalid");
        }
    }

    @Nested
    @DisplayName("Utility Methods")
    class UtilityMethods {

        @Test
        @DisplayName("Should return seconds remaining")
        void shouldReturnSecondsRemaining() {
            TOTP totp = TOTP.defaultInstance();

            int remaining = totp.getSecondsRemaining();

            assertThat(remaining).isBetween(1, 30);
        }

        @Test
        @DisplayName("Should return current counter")
        void shouldReturnCurrentCounter() {
            TOTP totp = TOTP.defaultInstance();

            long counter = totp.getCurrentCounter();
            long expected = System.currentTimeMillis() / 1000 / 30;

            assertThat(counter).isEqualTo(expected);
        }
    }
}
