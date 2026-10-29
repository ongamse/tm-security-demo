package org.joychou.security;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Allowlist based parser for user supplied commands. The returned argv is meant to be
 * passed directly to {@link ProcessBuilder} / {@link Runtime#exec(String[])} so that no shell is involved.
 */
public final class CommandAllowlist {

    private static final Set<String> ALLOWED_COMMANDS = Collections.unmodifiableSet(
            new HashSet<String>(Arrays.asList("whoami", "id", "pwd", "date", "uname", "hostname", "ls")));

    private static final Pattern ARG_PATTERN = Pattern.compile("^[a-zA-Z0-9_/\\.=-]+$");

    private static final int MAX_ARGS = 8;

    private CommandAllowlist() {
    }

    /**
     * @param cmd user supplied command line
     * @return argv array if the executable is allowlisted and every argument is made of safe characters,
     * otherwise null
     */
    public static String[] parse(String cmd) {
        if (cmd == null) {
            return null;
        }
        String trimmed = cmd.trim();
        if (trimmed.isEmpty()) {
            return null;
        }
        String[] argv = trimmed.split("\\s+");
        if (argv.length > MAX_ARGS || !ALLOWED_COMMANDS.contains(argv[0])) {
            return null;
        }
        for (int i = 1; i < argv.length; i++) {
            if (!ARG_PATTERN.matcher(argv[i]).matches()) {
                return null;
            }
        }
        return argv;
    }
}
