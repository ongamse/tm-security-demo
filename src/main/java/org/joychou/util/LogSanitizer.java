package org.joychou.util;

/**
 * Neutralizes untrusted data before it is written to a log (CWE-117 log forging).
 */
public final class LogSanitizer {

    private static final int MAX_LENGTH = 200;

    private LogSanitizer() {
    }

    /**
     * Replace CR, LF, all other control characters and the Unicode line/paragraph separators
     * with '_' and truncate the result.
     *
     * @param value untrusted value (may be null)
     * @return a single-line, bounded string that is safe to log
     */
    public static String clean(Object value) {
        if (value == null) {
            return "null";
        }
        String s = String.valueOf(value);
        boolean truncated = s.length() > MAX_LENGTH;
        if (truncated) {
            s = s.substring(0, MAX_LENGTH);
        }
        StringBuilder sb = new StringBuilder(s.length() + 3);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            int type = Character.getType(c);
            if (Character.isISOControl(c) || type == Character.LINE_SEPARATOR
                    || type == Character.PARAGRAPH_SEPARATOR) {
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
