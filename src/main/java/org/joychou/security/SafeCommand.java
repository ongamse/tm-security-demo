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
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

/**
 * Runs a small allowlist of read-only commands on behalf of untrusted text.
 *
 * <p>No shell is ever involved. The executable and every option are taken from constant
 * allowlist tables (the untrusted text is only used as a lookup key, never copied into argv).
 * The only free-form argv elements are a path or a host that match a strict regex, cannot start
 * with '-', and cannot contain '..'; they are always placed after a fixed '--' terminator where
 * the tool supports it.
 */
public final class SafeCommand {

    private static final long TIMEOUT_SECONDS = 10L;
    private static final int MAX_CMD_LENGTH = 256;
    private static final int MAX_OUTPUT_CHARS = 1 << 20;

    /** Allowed command name -> constant executable name. */
    private static final Map<String, String> EXECUTABLES;

    /** Allowed ls option -> constant option. */
    private static final Map<String, String> LS_OPTIONS;

    static {
        Map<String, String> exe = new HashMap<>();
        exe.put("whoami", "whoami");
        exe.put("id", "id");
        exe.put("pwd", "pwd");
        exe.put("date", "date");
        exe.put("hostname", "hostname");
        exe.put("uname", "uname");
        exe.put("ls", "ls");
        EXECUTABLES = Collections.unmodifiableMap(exe);

        Map<String, String> ls = new HashMap<>();
        ls.put("-l", "-l");
        ls.put("-a", "-a");
        ls.put("-la", "-la");
        ls.put("-al", "-al");
        ls.put("-lh", "-lh");
        ls.put("-1", "-1");
        LS_OPTIONS = Collections.unmodifiableMap(ls);
    }

    private static final String LS = "ls";
    private static final String CURL = "curl";
    private static final String END_OF_OPTIONS = "--";

    private static final Pattern PATH_PATTERN = Pattern.compile("^[A-Za-z0-9_/][A-Za-z0-9_/.-]{0,254}$");
    private static final Pattern HOST_PATTERN = Pattern.compile("^[A-Za-z0-9][A-Za-z0-9.-]{0,252}(:[0-9]{1,5})?$");

    private SafeCommand() {
    }

    /**
     * Validate a filesystem path used as a single argv element.
     *
     * @return the path when valid, otherwise null
     */
    public static String checkPath(String path) {
        if (path == null || !PATH_PATTERN.matcher(path).matches() || path.contains("..")) {
            return null;
        }
        return path;
    }

    /**
     * Validate a host[:port] value (e.g. the Host header) for use as a single argv element.
     *
     * @return the host when valid, otherwise null
     */
    public static String checkHost(String host) {
        if (host == null || !HOST_PATTERN.matcher(host).matches() || host.contains("..")) {
            return null;
        }
        return host;
    }

    /**
     * Run an allowlisted command given as text (e.g. "ls -la /tmp").
     *
     * @param cmd         untrusted command text
     * @param mergeStderr whether stderr is merged into the returned output
     * @return process output, or null when the command or any argument is not allowed
     */
    public static String runCommand(String cmd, boolean mergeStderr) throws IOException {
        if (cmd == null || cmd.length() > MAX_CMD_LENGTH || cmd.trim().isEmpty()) {
            return null;
        }
        String[] parts = cmd.trim().split("\\s+");
        String exe = EXECUTABLES.get(parts[0]);
        if (exe == null) {
            return null;
        }
        List<String> argv = new ArrayList<>();
        argv.add(exe);
        if (LS.equals(exe)) {
            int i = 1;
            while (i < parts.length && parts[i].startsWith("-")) {
                String opt = LS_OPTIONS.get(parts[i]);
                if (opt == null) {
                    return null;
                }
                argv.add(opt);
                i++;
            }
            if (i < parts.length) {
                if (i != parts.length - 1) {
                    return null;
                }
                String path = checkPath(parts[i]);
                if (path == null) {
                    return null;
                }
                argv.add(END_OF_OPTIONS);
                argv.add(path);
            }
        } else if (parts.length > 1) {
            return null;
        }
        return execute(argv, mergeStderr);
    }

    /**
     * List a directory with a fixed "ls -la --" command.
     *
     * @return output, or null when the path is not allowed
     */
    public static String listDirectory(String path) throws IOException {
        String checked = checkPath(path);
        if (checked == null) {
            return null;
        }
        List<String> argv = new ArrayList<>();
        argv.add(LS);
        argv.add("-la");
        argv.add(END_OF_OPTIONS);
        argv.add(checked);
        return execute(argv, true);
    }

    /**
     * Fetch a validated host with a fixed "curl" command (no extra options).
     *
     * @return output, or null when the host is not allowed
     */
    public static String curlHost(String host) throws IOException {
        String checked = checkHost(host);
        if (checked == null) {
            return null;
        }
        List<String> argv = new ArrayList<>();
        argv.add(CURL);
        argv.add(checked);
        return execute(argv, true);
    }

    /** Single process-spawn site. argv[0] is always one of the constants above; no shell. */
    private static String execute(List<String> argv, boolean mergeStderr) throws IOException {
        ProcessBuilder builder = new ProcessBuilder(argv);
        builder.redirectErrorStream(mergeStderr);
        Process process = builder.start();
        StringBuilder sb = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null && sb.length() < MAX_OUTPUT_CHARS) {
                sb.append(line).append('\n');
            }
        } finally {
            try {
                if (!process.waitFor(TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
                    process.destroyForcibly();
                }
            } catch (InterruptedException e) {
                process.destroyForcibly();
                Thread.currentThread().interrupt();
            }
        }
        return sb.toString();
    }
}
