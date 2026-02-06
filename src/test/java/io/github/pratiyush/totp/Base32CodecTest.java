package io.github.pratiyush.totp;

import io.github.pratiyush.totp.internal.Base32Codec;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.*;

/**
 * Tests for Base32 codec.
 */
@DisplayName("Base32 Codec Tests")
class Base32CodecTest {

    @Nested
    @DisplayName("Encoding")
    class Encoding {

        @Test
        @DisplayName("Should encode empty array")
        void shouldEncodeEmpty() {
            String result = Base32Codec.encode(new byte[0]);
            assertThat(result).isEmpty();
        }

        @ParameterizedTest
        @DisplayName("Should encode known values")
        @CsvSource({
                "'', ''",
                "'f', 'MY'",
                "'fo', 'MZXQ'",
                "'foo', 'MZXW6'",
                "'foob', 'MZXW6YQ'",
                "'fooba', 'MZXW6YTB'",
                "'foobar', 'MZXW6YTBOI'"
        })
        void shouldEncodeKnownValues(String input, String expected) {
            byte[] bytes = input.getBytes();
            String result = Base32Codec.encode(bytes);
            assertThat(result).isEqualTo(expected);
        }

        @Test
        @DisplayName("Should encode with padding")
        void shouldEncodeWithPadding() {
            byte[] bytes = "f".getBytes();
            String result = Base32Codec.encode(bytes, true);
            assertThat(result).isEqualTo("MY======");
        }

        @Test
        @DisplayName("Should encode binary data")
        void shouldEncodeBinaryData() throws TOTPException {
            byte[] bytes = { (byte) 0xFF, (byte) 0x00, (byte) 0xAB };
            String result = Base32Codec.encode(bytes);
            assertThat(result).isNotEmpty();

            // Verify round-trip
            byte[] decoded = Base32Codec.decode(result);
            assertThat(decoded).isEqualTo(bytes);
        }
    }

    @Nested
    @DisplayName("Decoding")
    class Decoding {

        @Test
        @DisplayName("Should decode empty string")
        void shouldDecodeEmpty() throws TOTPException {
            byte[] result = Base32Codec.decode("");
            assertThat(result).isEmpty();
        }

        @ParameterizedTest
        @DisplayName("Should decode known values")
        @CsvSource({
                "'MY', 'f'",
                "'MZXQ', 'fo'",
                "'MZXW6', 'foo'",
                "'MZXW6YQ', 'foob'",
                "'MZXW6YTB', 'fooba'",
                "'MZXW6YTBOI', 'foobar'"
        })
        void shouldDecodeKnownValues(String input, String expected) throws TOTPException {
            byte[] result = Base32Codec.decode(input);
            assertThat(new String(result)).isEqualTo(expected);
        }

        @Test
        @DisplayName("Should decode case-insensitive")
        void shouldDecodeCaseInsensitive() throws TOTPException {
            byte[] upper = Base32Codec.decode("MZXW6YTBOI");
            byte[] lower = Base32Codec.decode("mzxw6ytboi");
            byte[] mixed = Base32Codec.decode("MzXw6YtBoI");

            assertThat(upper).isEqualTo(lower).isEqualTo(mixed);
        }

        @Test
        @DisplayName("Should decode with padding")
        void shouldDecodeWithPadding() throws TOTPException {
            byte[] result = Base32Codec.decode("MY======");
            assertThat(new String(result)).isEqualTo("f");
        }

        @Test
        @DisplayName("Should decode without padding")
        void shouldDecodeWithoutPadding() throws TOTPException {
            byte[] result = Base32Codec.decode("MY");
            assertThat(new String(result)).isEqualTo("f");
        }

        @Test
        @DisplayName("Should ignore whitespace")
        void shouldIgnoreWhitespace() throws TOTPException {
            byte[] result = Base32Codec.decode("MZXW 6YTB OI");
            assertThat(new String(result)).isEqualTo("foobar");
        }

        @Test
        @DisplayName("Should reject null")
        void shouldRejectNull() {
            assertThatThrownBy(() -> Base32Codec.decode(null))
                    .isInstanceOf(TOTPException.class);
        }

        @ParameterizedTest
        @DisplayName("Should reject invalid characters")
        @ValueSource(strings = { "INVALID!", "ABC0DEF", "ABC1DEF", "ABC8DEF", "ABC9DEF", "ABC@DEF" })
        void shouldRejectInvalidCharacters(String input) {
            assertThatThrownBy(() -> Base32Codec.decode(input))
                    .isInstanceOf(TOTPException.class)
                    .hasMessageContaining("Invalid Base32");
        }
    }

    @Nested
    @DisplayName("Validation")
    class Validation {

        @ParameterizedTest
        @DisplayName("Should validate correct Base32")
        @ValueSource(strings = { "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", "abcdefghijklmnop", "MZXW6YTBOI" })
        void shouldValidateCorrect(String input) {
            assertThat(Base32Codec.isValid(input)).isTrue();
        }

        @ParameterizedTest
        @DisplayName("Should invalidate incorrect Base32")
        @ValueSource(strings = { "INVALID!", "ABC01DEF", "ABC89DEF" })
        void shouldInvalidateIncorrect(String input) {
            assertThat(Base32Codec.isValid(input)).isFalse();
        }

        @Test
        @DisplayName("Should invalidate null and empty")
        void shouldInvalidateNullAndEmpty() {
            assertThat(Base32Codec.isValid(null)).isFalse();
            assertThat(Base32Codec.isValid("")).isFalse();
        }
    }

    @Nested
    @DisplayName("Round-Trip")
    class RoundTrip {

        @Test
        @DisplayName("Should round-trip random bytes")
        void shouldRoundTripRandomBytes() throws TOTPException {
            for (int length = 1; length <= 64; length++) {
                byte[] original = SecretGenerator.generateBytes(length);
                String encoded = Base32Codec.encode(original);
                byte[] decoded = Base32Codec.decode(encoded);

                assertThat(decoded)
                        .as("Round-trip for %d bytes", length)
                        .isEqualTo(original);
            }
        }

        @Test
        @DisplayName("Should round-trip TOTP secret")
        void shouldRoundTripTOTPSecret() throws TOTPException {
            String secret = SecretGenerator.generate();
            byte[] decoded = Base32Codec.decode(secret);
            String reencoded = Base32Codec.encode(decoded);

            // Should be equivalent (may differ in padding)
            assertThat(Base32Codec.decode(reencoded)).isEqualTo(decoded);
        }
    }

    @Nested
    @DisplayName("Length Calculations")
    class LengthCalculations {

        @ParameterizedTest
        @DisplayName("Should calculate encoded length correctly")
        @CsvSource({
                "0, 0",
                "1, 2",
                "5, 8",
                "10, 16",
                "20, 32"
        })
        void shouldCalculateEncodedLength(int inputBytes, int expectedChars) {
            int actual = Base32Codec.encodedLength(inputBytes);
            assertThat(actual).isEqualTo(expectedChars);
        }

        @ParameterizedTest
        @DisplayName("Should calculate decoded length correctly")
        @CsvSource({
                "0, 0",
                "2, 1",
                "8, 5",
                "16, 10",
                "32, 20"
        })
        void shouldCalculateDecodedLength(int encodedChars, int expectedBytes) {
            int actual = Base32Codec.decodedLength(encodedChars);
            assertThat(actual).isEqualTo(expectedBytes);
        }
    }
}
