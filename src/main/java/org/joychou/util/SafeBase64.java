package org.joychou.util;

import java.util.Base64;
import java.util.regex.Pattern;

/**
 * Bounded Base64 decoding for attacker-controlled input (CVE-2026-114938).
 * Validates length and charset before the JDK decoder is invoked.
 */
public final class SafeBase64 {

    private static final Pattern STANDARD_ALPHABET = Pattern.compile("^[A-Za-z0-9+/]*={0,2}$");
    private static final Pattern JWT_ALPHABET = Pattern.compile("^[A-Za-z0-9_-]+(\\.[A-Za-z0-9_-]*){0,2}$");

    private SafeBase64() {
    }

    /**
     * Decode standard Base64 after validating charset and size.
     *
     * @param input     untrusted Base64 text
     * @param maxLength maximum accepted length of the encoded text
     * @return decoded bytes
     * @throws IllegalArgumentException if input is null, too long, or not valid Base64
     */
    public static byte[] decode(String input, int maxLength) {
        if (input == null) {
            throw new IllegalArgumentException("Base64 input is null");
        }
        if (input.length() > maxLength) {
            throw new IllegalArgumentException("Base64 input too long");
        }
        if (!STANDARD_ALPHABET.matcher(input).matches()) {
            throw new IllegalArgumentException("Illegal base64 character");
        }
        return Base64.getDecoder().decode(input);
    }

    /**
     * Check that a JWT (base64url segments separated by dots) is within size bounds
     * and uses only the base64url alphabet, before a library decodes it.
     */
    public static boolean isWellFormedJwt(String token, int maxLength) {
        return token != null
                && token.length() <= maxLength
                && JWT_ALPHABET.matcher(token).matches();
    }
}
