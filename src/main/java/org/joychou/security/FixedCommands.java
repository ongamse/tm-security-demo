package org.joychou.security;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Server-side catalogue of the only external programs the demo endpoints may run.
 * A request value is only ever a <em>key</em> into this catalogue; the argv that is
 * executed is always one of the constant arrays below, never request-derived text.
 */
public final class FixedCommands {

    private static final Map<String, String[]> COMMANDS;

    static {
        Map<String, String[]> m = new LinkedHashMap<String, String[]>();
        m.put("whoami", new String[]{"whoami"});
        m.put("pwd", new String[]{"pwd"});
        m.put("date", new String[]{"date"});
        m.put("id", new String[]{"id"});
        m.put("uname", new String[]{"uname"});
        m.put("hostname", new String[]{"hostname"});
        m.put("uptime", new String[]{"uptime"});
        m.put("list", new String[]{"ls", "-la", "/tmp"});
        COMMANDS = Collections.unmodifiableMap(m);
    }

    private FixedCommands() {
    }

    /**
     * Resolve a command key to its constant argv.
     *
     * @param key key chosen by the caller, e.g. "whoami" or "list"
     * @return a copy of the constant argv, or null when the key is unknown
     */
    public static String[] lookup(String key) {
        if (key == null) {
            return null;
        }
        // Compare against the catalogue and return the catalogue's own value, so the
        // returned argv is never the caller-supplied string.
        for (Map.Entry<String, String[]> entry : COMMANDS.entrySet()) {
            if (entry.getKey().equals(key.trim())) {
                return entry.getValue().clone();
            }
        }
        return null;
    }
}
