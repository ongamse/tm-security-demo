package org.joychou.util;

/**
 * Neutralizes untrusted values before they are written to a log (CWE-117, log forging).
 * CR, LF, tab and every other control character, as well as the Unicode line / paragraph
 * separators (U+2028, U+2029) and NEL (U+0085), are replaced by '_' and the result is truncated.
 */
public final class LogSanitizer {

    private static final int MAX_LENGTH = 200;

    private LogSanitizer() {
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
