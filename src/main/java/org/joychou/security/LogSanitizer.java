package org.joychou.security;

/**
 * Neutralizes untrusted values before they are written to logs (CWE-117 log forging).
 */
public final class LogSanitizer {

    private static final int MAX_LENGTH = 500;

    private LogSanitizer() {
    }

    /**
     * Returns a new string in which CR, LF, TAB, other ISO control characters and the
     * Unicode line/paragraph separators are replaced by '_', truncated to 500 characters.
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
            char c = str.charAt(i);
            if (Character.isISOControl(c) || c == '\u2028' || c == '\u2029') {
                sb.append('_');
            } else {
                sb.append(c);
            }
        }
        if (truncated) {
            sb.append("...");
        }
        return sb.toString();
    }
}
