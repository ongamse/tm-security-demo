package org.joychou.util;

/**
 * Helpers that keep request derived values from forging log lines (CWE-117).
 */
public final class LogUtils {

    private static final int MAX_LOG_VALUE_LENGTH = 200;

    private LogUtils() {
    }

    /**
     * Replace CR, LF, tab and all other control characters with an underscore and truncate the
     * value, so that an attacker can not inject additional log lines or break the log format.
     */
    public static String sanitize(String value) {
        if (value == null) {
            return "null";
        }
        String cleaned = value.replaceAll("[\\r\\n\\t\\x00-\\x1F\\x7F]", "_");
        if (cleaned.length() > MAX_LOG_VALUE_LENGTH) {
            cleaned = cleaned.substring(0, MAX_LOG_VALUE_LENGTH) + "...";
        }
        return cleaned;
    }

    /**
     * Sanitized form of a throwable for logging: only the class name and the sanitized message.
     */
    public static String sanitize(Throwable t) {
        if (t == null) {
            return "null";
        }
        return t.getClass().getName() + ": " + sanitize(t.getMessage());
    }
}
