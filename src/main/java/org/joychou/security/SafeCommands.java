package org.joychou.security;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Server-owned catalog of commands that may be run on behalf of a request.
 * <p>
 * A request value is only ever used as a <em>selector</em>: it is compared against the catalog
 * keys and the matching, constant argv array owned by this class is returned. No part of the
 * request value is ever copied into the argv that is handed to ProcessBuilder.
 */
public final class SafeCommands {

    private static final Map<String, String[]> CATALOG;

    static {
        Map<String, String[]> m = new LinkedHashMap<String, String[]>();
        m.put("whoami", new String[]{"whoami"});
        m.put("id", new String[]{"id"});
        m.put("date", new String[]{"date"});
        m.put("hostname", new String[]{"hostname"});
        m.put("uname", new String[]{"uname"});
        m.put("pwd", new String[]{"pwd"});
        m.put("uptime", new String[]{"uptime"});
        CATALOG = Collections.unmodifiableMap(m);
    }

    private SafeCommands() {
    }

    /**
     * Resolve a request supplied token to a constant argv.
     *
     * @param token request supplied command name
     * @return a copy of the catalog's constant argv, or null if the token is unknown
     */
    public static String[] lookup(String token) {
        if (token == null) {
            return null;
        }
        String wanted = token.trim();
        for (Map.Entry<String, String[]> entry : CATALOG.entrySet()) {
            if (entry.getKey().equals(wanted)) {
                // The returned array comes from the catalog, not from the request.
                return entry.getValue().clone();
            }
        }
        return null;
    }
}
