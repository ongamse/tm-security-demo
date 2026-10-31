package org.joychou.util;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Neutralizes untrusted values before they are written to a log (CWE-117, log forging).
 * CR, LF, tab and every other control character, as well as the Unicode line / paragraph
 * separators (U+2028, U+2029) and NEL (U+0085), are replaced by '_' and the result is truncated.
 */
public final class LogSanitizer {

    private static final int MAX_LENGTH = 200;
    private static final int FINGERPRINT_HEX_LENGTH = 16;
    private static final String HMAC_ALGORITHM = "HmacSHA256";
    // Per-process random key: fingerprints are only comparable within one JVM run and cannot be
    // reversed with precomputed (unsalted) hash tables.
    private static final SecretKeySpec HMAC_KEY = newRandomKey();

    private LogSanitizer() {
    }

    private static SecretKeySpec newRandomKey() {
        byte[] key = new byte[32];
        new SecureRandom().nextBytes(key);
        return new SecretKeySpec(key, HMAC_ALGORITHM);
    }

    /**
     * Returns a short hex SHA-256 fingerprint of the value so that correlated log lines can be
     * matched without ever writing request-derived text to the log. Hex digits cannot contain
     * CR/LF or any other control character.
     */
    public static String fingerprint(Object value) {
        if (value == null) {
            return "null";
        }
        try {
            Mac mac = Mac.getInstance(HMAC_ALGORITHM);
            mac.init(HMAC_KEY);
            byte[] hash = mac.doFinal(String.valueOf(value).getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(FINGERPRINT_HEX_LENGTH);
            for (int i = 0; i < FINGERPRINT_HEX_LENGTH / 2; i++) {
                sb.append(Character.forDigit((hash[i] >> 4) & 0xF, 16));
                sb.append(Character.forDigit(hash[i] & 0xF, 16));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            return "unavailable";
        }
    }

    public static String clean(Object value) {
        if (value == null) {
            return "null";
        }
        String text = String.valueOf(value);
        int length = Math.min(text.length(), MAX_LENGTH);
        StringBuilder sb = new StringBuilder(length + 3);
        for (int i = 0; i < length; i++) {
            char c = text.charAt(i);
            // numeric code points: U+0085 NEL, U+2028 LINE SEPARATOR, U+2029 PARAGRAPH SEPARATOR
            if (Character.isISOControl(c) || c == 0x0085 || c == 0x2028 || c == 0x2029) {
                sb.append('_');
            } else {
                sb.append(c);
            }
        }
        if (text.length() > MAX_LENGTH) {
            sb.append("...");
        }
        return sb.toString();
    }
}
