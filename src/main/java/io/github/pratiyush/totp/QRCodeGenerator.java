package io.github.pratiyush.totp;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.WriterException;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Base64;
import java.util.Objects;

/**
 * Generates QR codes for TOTP secrets compatible with authenticator apps.
 * 
 * <p>
 * This class creates QR codes containing otpauth:// URIs that can be
 * scanned by Google Authenticator, Microsoft Authenticator, and other
 * compatible apps.
 * </p>
 * 
 * <h2>Dependencies</h2>
 * <p>
 * Requires ZXing library (optional dependency). If ZXing is not available,
 * methods will throw {@code NoClassDefFoundError}.
 * </p>
 * 
 * <h2>Usage Examples</h2>
 * 
 * <pre>{@code
 * // Generate QR code as BufferedImage
 * BufferedImage qr = QRCodeGenerator.generateImage(
 *         secret, "user@example.com", "MyApp", 250);
 * 
 * // Save to file
 * QRCodeGenerator.saveToFile(secret, "user@example.com", "MyApp",
 *         Path.of("qr.png"), 250);
 * 
 * // Get as Base64 for embedding in HTML
 * String base64 = QRCodeGenerator.generateBase64(
 *         secret, "user@example.com", "MyApp", 250);
 * String html = "<img src='data:image/png;base64," + base64 + "'/>";
 * }</pre>
 * 
 * <h2>otpauth URI Format</h2>
 * <p>
 * Generated URIs follow the format:
 * </p>
 * 
 * <pre>
 * {@code
 * otpauth://totp/{issuer}:{account}?secret={secret}&issuer={issuer}&algorithm={algo}&digits={digits}&period={period}
 * }
 * </pre>
 * 
 * @see <a href=
 *      "https://github.com/google/google-authenticator/wiki/Key-Uri-Format">Key
 *      URI Format</a>
 */
public final class QRCodeGenerator {

    /** Default QR code foreground color (black) */
    private static final int DEFAULT_FOREGROUND = 0xFF000000;

    /** Default QR code background color (white) */
    private static final int DEFAULT_BACKGROUND = 0xFFFFFFFF;

    /** Default QR code size in pixels */
    public static final int DEFAULT_SIZE = 250;

    /** Minimum QR code size in pixels */
    public static final int MIN_SIZE = 100;

    /** Maximum QR code size in pixels */
    public static final int MAX_SIZE = 1000;

    private QRCodeGenerator() {
        // Utility class
    }

    // ========================================================================
    // URI Generation
    // ========================================================================

    /**
     * Builds an otpauth URI for TOTP.
     * 
     * @param secret  the Base32 encoded secret
     * @param account the account name (typically email)
     * @param issuer  the service name
     * @param config  optional configuration (null for defaults)
     * @return the otpauth URI
     * @throws TOTPException if parameters are invalid
     */
    public static String buildOtpauthUri(final String secret, final String account,
            final String issuer, final TOTPConfig config)
            throws TOTPException {
        validateParameters(secret, account, issuer);

        TOTPConfig cfg = config != null ? config : TOTPConfig.defaultConfig();

        StringBuilder uri = new StringBuilder("otpauth://totp/");

        // Label: issuer:account
        uri.append(urlEncode(issuer)).append(":").append(urlEncode(account));

        // Parameters
        uri.append("?secret=").append(secret.toUpperCase().replaceAll("\\s", ""));
        uri.append("&issuer=").append(urlEncode(issuer));

        // Only include non-default values
        if (cfg.getAlgorithm() != Algorithm.SHA1) {
            uri.append("&algorithm=").append(cfg.getAlgorithm().getOtpauthName());
        }
        if (cfg.getDigits() != 6) {
            uri.append("&digits=").append(cfg.getDigits());
        }
        if (cfg.getPeriodSeconds() != 30) {
            uri.append("&period=").append(cfg.getPeriodSeconds());
        }

        return uri.toString();
    }

    /**
     * Builds an otpauth URI with default configuration.
     * 
     * @param secret  the Base32 encoded secret
     * @param account the account name
     * @param issuer  the service name
     * @return the otpauth URI
     * @throws TOTPException if parameters are invalid
     */
    public static String buildOtpauthUri(final String secret, final String account,
            final String issuer) throws TOTPException {
        return buildOtpauthUri(secret, account, issuer, null);
    }

    // ========================================================================
    // QR Code Generation
    // ========================================================================

    /**
     * Generates a QR code image.
     * 
     * @param secret  the Base32 encoded secret
     * @param account the account name
     * @param issuer  the service name
     * @param size    the image size in pixels
     * @return the QR code as BufferedImage
     * @throws TOTPException if generation fails
     */
    public static BufferedImage generateImage(final String secret, final String account,
            final String issuer, final int size)
            throws TOTPException {
        return generateImage(secret, account, issuer, size, null);
    }

    /**
     * Generates a QR code image with custom configuration.
     * 
     * @param secret  the Base32 encoded secret
     * @param account the account name
     * @param issuer  the service name
     * @param size    the image size in pixels
     * @param config  optional TOTP configuration
     * @return the QR code as BufferedImage
     * @throws TOTPException if generation fails
     */
    public static BufferedImage generateImage(final String secret, final String account,
            final String issuer, final int size,
            final TOTPConfig config)
            throws TOTPException {
        validateSize(size);

        String uri = buildOtpauthUri(secret, account, issuer, config);

        try {
            QRCodeWriter writer = new QRCodeWriter();
            BitMatrix matrix = writer.encode(uri, BarcodeFormat.QR_CODE, size, size);

            BufferedImage image = new BufferedImage(size, size, BufferedImage.TYPE_INT_RGB);
            for (int x = 0; x < size; x++) {
                for (int y = 0; y < size; y++) {
                    image.setRGB(x, y, matrix.get(x, y) ? DEFAULT_FOREGROUND : DEFAULT_BACKGROUND);
                }
            }

            return image;
        } catch (WriterException e) {
            throw TOTPException.qrGenerationError(e);
        }
    }

    /**
     * Generates a QR code as Base64 encoded PNG.
     * 
     * <p>
     * The result can be used directly in HTML img tags:
     * </p>
     * 
     * <pre>{@code
     * <img src="data:image/png;base64,{result}" />
     * }</pre>
     * 
     * @param secret  the Base32 encoded secret
     * @param account the account name
     * @param issuer  the service name
     * @param size    the image size in pixels
     * @return Base64 encoded PNG
     * @throws TOTPException if generation fails
     */
    public static String generateBase64(final String secret, final String account,
            final String issuer, final int size)
            throws TOTPException {
        return generateBase64(secret, account, issuer, size, null);
    }

    /**
     * Generates a QR code as Base64 encoded PNG with custom configuration.
     * 
     * @param secret  the Base32 encoded secret
     * @param account the account name
     * @param issuer  the service name
     * @param size    the image size in pixels
     * @param config  optional TOTP configuration
     * @return Base64 encoded PNG
     * @throws TOTPException if generation fails
     */
    public static String generateBase64(final String secret, final String account,
            final String issuer, final int size,
            final TOTPConfig config)
            throws TOTPException {
        BufferedImage image = generateImage(secret, account, issuer, size, config);

        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            ImageIO.write(image, "PNG", baos);
            return Base64.getEncoder().encodeToString(baos.toByteArray());
        } catch (IOException e) {
            throw TOTPException.qrGenerationError(e);
        }
    }

    /**
     * Generates a data URI for embedding in HTML.
     * 
     * @param secret  the Base32 encoded secret
     * @param account the account name
     * @param issuer  the service name
     * @param size    the image size in pixels
     * @return data URI (data:image/png;base64,...)
     * @throws TOTPException if generation fails
     */
    public static String generateDataUri(final String secret, final String account,
            final String issuer, final int size)
            throws TOTPException {
        return "data:image/png;base64," + generateBase64(secret, account, issuer, size);
    }

    /**
     * Saves a QR code to a file.
     * 
     * @param secret  the Base32 encoded secret
     * @param account the account name
     * @param issuer  the service name
     * @param path    the file path
     * @param size    the image size in pixels
     * @throws TOTPException if generation or writing fails
     */
    public static void saveToFile(final String secret, final String account,
            final String issuer, final Path path, final int size)
            throws TOTPException {
        saveToFile(secret, account, issuer, path, size, null);
    }

    /**
     * Saves a QR code to a file with custom configuration.
     * 
     * @param secret  the Base32 encoded secret
     * @param account the account name
     * @param issuer  the service name
     * @param path    the file path
     * @param size    the image size in pixels
     * @param config  optional TOTP configuration
     * @throws TOTPException if generation or writing fails
     */
    public static void saveToFile(final String secret, final String account,
            final String issuer, final Path path, final int size,
            final TOTPConfig config)
            throws TOTPException {
        Objects.requireNonNull(path, "Path must not be null");

        BufferedImage image = generateImage(secret, account, issuer, size, config);

        try {
            String format = getFormatFromPath(path);
            ImageIO.write(image, format, path.toFile());
        } catch (IOException e) {
            throw TOTPException.qrGenerationError(e);
        }
    }

    /**
     * Writes a QR code to an output stream.
     * 
     * @param secret  the Base32 encoded secret
     * @param account the account name
     * @param issuer  the service name
     * @param out     the output stream
     * @param format  the image format (PNG, JPEG, etc.)
     * @param size    the image size in pixels
     * @throws TOTPException if generation or writing fails
     */
    public static void writeTo(final String secret, final String account,
            final String issuer, final OutputStream out,
            final String format, final int size)
            throws TOTPException {
        Objects.requireNonNull(out, "OutputStream must not be null");
        Objects.requireNonNull(format, "Format must not be null");

        BufferedImage image = generateImage(secret, account, issuer, size);

        try {
            ImageIO.write(image, format, out);
        } catch (IOException e) {
            throw TOTPException.qrGenerationError(e);
        }
    }

    // ========================================================================
    // Validation
    // ========================================================================

    private static void validateParameters(String secret, String account, String issuer)
            throws TOTPException {
        if (secret == null || secret.isBlank()) {
            throw TOTPException.invalidSecret("Secret cannot be null or empty");
        }
        if (account == null || account.isBlank()) {
            throw TOTPException.invalidConfig("Account cannot be null or empty");
        }
        if (issuer == null || issuer.isBlank()) {
            throw TOTPException.invalidConfig("Issuer cannot be null or empty");
        }
        if (account.contains(":")) {
            throw TOTPException.invalidConfig("Account cannot contain ':'");
        }
    }

    private static void validateSize(int size) throws TOTPException {
        if (size < MIN_SIZE || size > MAX_SIZE) {
            throw TOTPException.invalidConfig(
                    String.format("Size must be between %d and %d, got %d", MIN_SIZE, MAX_SIZE, size));
        }
    }

    private static String urlEncode(String value) {
        try {
            return URLEncoder.encode(value, StandardCharsets.UTF_8.name())
                    .replace("+", "%20");
        } catch (UnsupportedEncodingException e) {
            // UTF-8 is always supported
            throw new RuntimeException(e);
        }
    }

    private static String getFormatFromPath(Path path) {
        String filename = path.getFileName().toString().toLowerCase();
        if (filename.endsWith(".jpg") || filename.endsWith(".jpeg")) {
            return "JPEG";
        } else if (filename.endsWith(".gif")) {
            return "GIF";
        } else {
            return "PNG";
        }
    }
}
