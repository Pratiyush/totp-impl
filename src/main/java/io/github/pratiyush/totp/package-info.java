/*
 * MIT License
 *
 * Copyright (c) 2026 Pratiyush Kumar Singh
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
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
package io.github.pratiyush.totp;
