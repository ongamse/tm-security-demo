package org.joychou.security;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Builds an argv for a small allowlist of read-only commands from untrusted text.
 * The result must be passed to {@link ProcessBuilder} directly (never through a shell).
 */
public final class SafeCommand {

    /** Allowed command name -> whether it may take (validated) arguments. */
    private static final Map<String, Boolean> ALLOWED = new HashMap<>();

    static {
        ALLOWED.put("whoami", false);
        ALLOWED.put("id", false);
        ALLOWED.put("pwd", false);
        ALLOWED.put("date", false);
        ALLOWED.put("hostname", false);
        ALLOWED.put("uname", false);
        ALLOWED.put("ls", true);
    }

    private static final Pattern HOST_PATTERN = Pattern.compile("^[A-Za-z0-9][A-Za-z0-9.-]*(:[0-9]{1,5})?$");

    private SafeCommand() {
    }

    /**
     * Parse untrusted command text into an argv.
     *
     * @param cmd untrusted command text, e.g. "ls -la /tmp"
     * @return immutable argv, or null when the command or any argument is not allowed
     */
    public static List<String> toArgv(String cmd) {
        if (cmd == null || cmd.trim().isEmpty()) {
            return null;
        }
        String[] parts = cmd.trim().split("\\s+");
        Boolean argsAllowed = ALLOWED.get(parts[0]);
        if (argsAllowed == null) {
            return null;
        }
        if (parts.length > 1 && !argsAllowed) {
            return null;
        }
        List<String> argv = new ArrayList<>();
        argv.add(parts[0]);
        for (int i = 1; i < parts.length; i++) {
            if (SecurityUtil.cmdFilter(parts[i]) == null) {
                return null;
            }
            argv.add(parts[i]);
        }
        return Collections.unmodifiableList(argv);
    }

    /**
     * Validate a host[:port] value (e.g. the Host header) for use as a single argv element.
     *
     * @param host untrusted host
     * @return the host when valid, otherwise null
     */
    public static String checkHost(String host) {
        if (host == null || !HOST_PATTERN.matcher(host).matches()) {
            return null;
        }
        return host;
    }

    /**
     * Run an already validated argv without a shell and return stdout (and stderr when requested).
     */
    public static String run(List<String> argv, boolean mergeStderr) throws IOException {
        ProcessBuilder builder = new ProcessBuilder(argv);
        builder.redirectErrorStream(mergeStderr);
        Process process = builder.start();
        StringBuilder sb = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                sb.append(line).append('\n');
            }
        }
        return sb.toString();
    }
}
