package org.joychou.security;

/**
 * Helpers to reference untrusted (request-derived) values in log messages without writing
 * attacker-controlled text (CR/LF, forged entries) into the log.
 */
public final class LogSafe {

    private LogSafe() {
    }

    /**
     * Non-reversible representation of a value: its length and the number of non-printable
     * characters. The output only contains "len=", "ctrl=" and digits.
     *
     * @param value untrusted value, may be null
     * @return e.g. "len=17 ctrl=0", or "null"
     */
    public static String fingerprint(String value) {
        if (value == null) {
            return "null";
        }
        int ctrl = 0;
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c < 0x20 || c == 0x7f) {
                ctrl++;
            }
        }
        return "len=" + value.length() + " ctrl=" + ctrl;
    }

    /**
     * Name of the exception class only; the message is dropped because it often echoes input.
     */
    public static String errorName(Throwable t) {
        return t == null ? "null" : t.getClass().getSimpleName();
    }
}
