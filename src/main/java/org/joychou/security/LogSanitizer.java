package org.joychou.security;

/**
 * Neutralizes untrusted values before they are written to logs (CWE-117 log forging).
 */
public final class LogSanitizer {

    private static final int MAX_LENGTH = 500;

    /** Printable ASCII (0x20-0x7E) only; no control characters, so no CR/LF can ever be emitted. */
    private static final String SAFE_ALPHABET =
            " !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~";

    private LogSanitizer() {
    }

    /**
     * Returns a new string built exclusively from the constant printable-ASCII alphabet.
     * Every input character that is not in the alphabet (control characters, line/paragraph
     * separators, non-ASCII) is emitted as '?'. Output is truncated to 500 characters.
     */
    public static String clean(Object value) {
        if (value == null) {
            return "null";
        }
        String str = String.valueOf(value);
        boolean truncated = str.length() > MAX_LENGTH;
        int len = truncated ? MAX_LENGTH : str.length();
        StringBuilder sb = new StringBuilder(len + 3);
        for (int i = 0; i < len; i++) {
            int idx = SAFE_ALPHABET.indexOf(str.charAt(i));
            sb.append(idx >= 0 ? SAFE_ALPHABET.charAt(idx) : '?');
        }
        if (truncated) {
            sb.append("...");
        }
        return sb.toString();
    }
}
