package org.joychou.util;

/**
 * Neutralizes untrusted data before it is written to a log (CWE-117 log forging).
 */
public final class LogSanitizer {

    private static final int MAX_LENGTH = 200;
    private static final char LINE_SEPARATOR = (char) 0x2028;
    private static final char PARAGRAPH_SEPARATOR = (char) 0x2029;

    private LogSanitizer() {
    }

    /**
     * Replace CR, LF and every other control character (and Unicode line/paragraph separators)
     * with an underscore and truncate to {@value #MAX_LENGTH} characters.
     *
     * @param value untrusted value, may be null
     * @return a single-line, bounded string that is safe to log
     */
    public static String clean(String value) {
        if (value == null) {
            return "null";
        }
        int len = Math.min(value.length(), MAX_LENGTH);
        StringBuilder sb = new StringBuilder(len + 3);
        for (int i = 0; i < len; i++) {
            char c = value.charAt(i);
            if (Character.isISOControl(c) || c == LINE_SEPARATOR || c == PARAGRAPH_SEPARATOR) {
                sb.append('_');
            } else {
                sb.append(c);
            }
        }
        if (value.length() > MAX_LENGTH) {
            sb.append("...");
        }
        return sb.toString();
    }
}
