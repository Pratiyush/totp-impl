package io.github.pratiyush.totp;

/**
 * Exception thrown for TOTP-related errors.
 * 
 * <p>
 * This is a checked exception to ensure callers explicitly handle error cases.
 * The exception is designed to prevent accidental leakage of sensitive
 * information
 * such as secrets or internal state.
 * </p>
 * 
 * <h2>Error Codes</h2>
 * <p>
 * Each exception includes an {@link ErrorCode} for programmatic error handling:
 * </p>
 * <ul>
 * <li>{@link ErrorCode#INVALID_SECRET} - Secret is null, empty, or
 * malformed</li>
 * <li>{@link ErrorCode#INVALID_CODE} - Code format is invalid</li>
 * <li>{@link ErrorCode#INVALID_CONFIG} - Configuration parameters are
 * invalid</li>
 * <li>{@link ErrorCode#HMAC_ERROR} - HMAC computation failed</li>
 * <li>{@link ErrorCode#QR_GENERATION_ERROR} - QR code generation failed</li>
 * <li>{@link ErrorCode#INTERNAL_ERROR} - Unexpected internal error</li>
 * </ul>
 * 
 * <h2>Security Note</h2>
 * <p>
 * Exception messages are sanitized to never include secrets or sensitive data.
 * Always use the provided factory methods rather than constructing exceptions
 * directly.
 * </p>
 */
public final class TOTPException extends Exception {

    private static final long serialVersionUID = 1L;

    /**
     * Error codes for programmatic error handling.
     */
    public enum ErrorCode {
        /** Secret is null, empty, too short, or contains invalid characters */
        INVALID_SECRET,

        /** Code format is invalid (wrong length, non-numeric, etc.) */
        INVALID_CODE,

        /** Configuration parameters are invalid */
        INVALID_CONFIG,

        /** HMAC computation failed (algorithm not available, etc.) */
        HMAC_ERROR,

        /** QR code generation failed */
        QR_GENERATION_ERROR,

        /** Unexpected internal error */
        INTERNAL_ERROR
    }

    private final ErrorCode errorCode;

    /**
     * Creates a new TOTP exception with the specified error code and message.
     * 
     * @param errorCode the error code
     * @param message   the error message (must not contain sensitive data)
     */
    private TOTPException(final ErrorCode errorCode, final String message) {
        super(message);
        this.errorCode = errorCode;
    }

    /**
     * Creates a new TOTP exception with the specified error code, message, and
     * cause.
     * 
     * @param errorCode the error code
     * @param message   the error message (must not contain sensitive data)
     * @param cause     the underlying cause
     */
    private TOTPException(final ErrorCode errorCode, final String message, final Throwable cause) {
        super(message, cause);
        this.errorCode = errorCode;
    }

    /**
     * Returns the error code for this exception.
     * 
     * @return the error code, never null
     */
    public ErrorCode getErrorCode() {
        return errorCode;
    }

    // ========================================================================
    // Factory methods for common error cases
    // ========================================================================

    /**
     * Creates an exception for invalid secrets.
     * 
     * @param reason the reason the secret is invalid (no sensitive data!)
     * @return new exception
     */
    public static TOTPException invalidSecret(final String reason) {
        return new TOTPException(ErrorCode.INVALID_SECRET,
                "Invalid secret: " + reason);
    }

    /**
     * Creates an exception for invalid codes.
     * 
     * @param reason the reason the code is invalid
     * @return new exception
     */
    public static TOTPException invalidCode(final String reason) {
        return new TOTPException(ErrorCode.INVALID_CODE,
                "Invalid code: " + reason);
    }

    /**
     * Creates an exception for invalid configuration.
     * 
     * @param reason the reason the configuration is invalid
     * @return new exception
     */
    public static TOTPException invalidConfig(final String reason) {
        return new TOTPException(ErrorCode.INVALID_CONFIG,
                "Invalid configuration: " + reason);
    }

    /**
     * Creates an exception for HMAC errors.
     * 
     * @param cause the underlying cause
     * @return new exception
     */
    public static TOTPException hmacError(final Throwable cause) {
        return new TOTPException(ErrorCode.HMAC_ERROR,
                "HMAC computation failed", cause);
    }

    /**
     * Creates an exception for QR generation errors.
     * 
     * @param cause the underlying cause
     * @return new exception
     */
    public static TOTPException qrGenerationError(final Throwable cause) {
        return new TOTPException(ErrorCode.QR_GENERATION_ERROR,
                "QR code generation failed", cause);
    }

    /**
     * Creates an exception for internal errors.
     * 
     * @param message the error message
     * @param cause   the underlying cause
     * @return new exception
     */
    public static TOTPException internalError(final String message, final Throwable cause) {
        return new TOTPException(ErrorCode.INTERNAL_ERROR, message, cause);
    }

    @Override
    public String toString() {
        return String.format("TOTPException[%s]: %s", errorCode, getMessage());
    }
}
