package org.joychou.security;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Helpers to reference untrusted (request-derived) values in log messages without writing
 * attacker-controlled text (CR/LF, forged entries) into the log.
 */
public final class LogSafe {

    private static final char[] HEX = "0123456789abcdef".toCharArray();
    private static final int DIGEST_HEX_CHARS = 12;

    private LogSafe() {
    }

    /**
     * Non-reversible representation of a value: its length and a SHA-256 hex digest prefix.
     * The output only contains digits, "len=", "sha256=" and lowercase hex characters.
     *
     * @param value untrusted value, may be null
     * @return e.g. "len=17 sha256=1a2b3c4d5e6f", or "null"
     */
    public static String fingerprint(String value) {
        if (value == null) {
            return "null";
        }
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(value.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(DIGEST_HEX_CHARS);
            for (int i = 0; sb.length() < DIGEST_HEX_CHARS && i < digest.length; i++) {
                sb.append(HEX[(digest[i] >> 4) & 0x0f]).append(HEX[digest[i] & 0x0f]);
            }
            return "len=" + value.length() + " sha256=" + sb;
        } catch (NoSuchAlgorithmException e) {
            return "len=" + value.length();
        }
    }

    /**
     * Name of the exception class only; the message is dropped because it often echoes input.
     */
    public static String errorName(Throwable t) {
        return t == null ? "null" : t.getClass().getSimpleName();
    }
}
