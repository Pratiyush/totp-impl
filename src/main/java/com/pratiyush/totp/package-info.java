/**
 * Production-Ready TOTP Library - Null Safety Declaration.
 * 
 * <p>
 * This package provides a secure, RFC 6238 compliant TOTP implementation
 * with constant-time verification and replay attack prevention.
 * </p>
 * 
 * <p>
 * This package uses jSpecify annotations for null safety:
 * <ul>
 * <li>{@code @NullMarked} - All types are non-null by default</li>
 * <li>{@code @Nullable} - Explicitly marks nullable types</li>
 * </ul>
 * 
 * @author Pratiyush Kumar Singh
 * @version 1.0.0
 * @since 1.0.0
 * @see <a href="https://jspecify.dev/">jSpecify</a>
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc6238">RFC 6238</a>
 */
@org.jspecify.annotations.NullMarked
package com.pratiyush.totp;
