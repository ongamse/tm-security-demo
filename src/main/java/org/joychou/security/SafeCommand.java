package org.joychou.security;

import org.joychou.util.HttpUtils;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.NotDirectoryException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.BasicFileAttributes;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Supports a small set of read-only "commands" on behalf of untrusted text.
 *
 * <p>No child process is ever started. The command name from the request only selects a fixed
 * branch; it is never passed on. Every result is produced by Java APIs: directory listings use
 * java.nio.file on a path confined to an allowed base directory, "curl" uses the SSRF-validated
 * HTTP client, and the fixed informational commands read JVM / OS properties.
 */
public final class SafeCommand {

    private static final int MAX_CMD_LENGTH = 256;
    private static final int MAX_OUTPUT_CHARS = 1 << 20;
    private static final int MAX_ENTRIES = 1000;

    private static final Set<String> LS_OPTIONS;

    static {
        Set<String> ls = new HashSet<>();
        ls.add("-l");
        ls.add("-a");
        ls.add("-la");
        ls.add("-al");
        ls.add("-lh");
        ls.add("-1");
        LS_OPTIONS = Collections.unmodifiableSet(ls);
    }

    private static final Pattern PATH_PATTERN = Pattern.compile("^[A-Za-z0-9_/][A-Za-z0-9_/.-]{0,254}$");
    private static final Pattern HOST_PATTERN = Pattern.compile("^[A-Za-z0-9][A-Za-z0-9.-]{0,252}(:[0-9]{1,5})?$");

    private SafeCommand() {
    }

    /**
     * Validate a filesystem path text.
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
     * Validate a host[:port] value (e.g. the Host header).
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
     * Handle an allowlisted command given as text (e.g. "ls -la /tmp").
     *
     * @param cmd         untrusted command text
     * @param mergeStderr kept for API compatibility; there is no process and hence no stderr
     * @return the output, or null when the command or any argument is not allowed
     */
    public static String runCommand(String cmd, boolean mergeStderr) throws IOException {
        if (cmd == null || cmd.length() > MAX_CMD_LENGTH || cmd.trim().isEmpty()) {
            return null;
        }
        String[] parts = cmd.trim().split("\\s+");
        String name = parts[0];
        if ("ls".equals(name)) {
            return runLs(parts);
        }
        if (parts.length > 1) {
            return null;
        }
        // The request text only selects a branch; the returned values come from Java APIs.
        switch (name) {
            case "whoami":
                return System.getProperty("user.name") + "\n";
            case "id":
                return "user=" + System.getProperty("user.name") + "\n";
            case "pwd":
                return Paths.get("").toAbsolutePath().toString() + "\n";
            case "date":
                return Instant.now().toString() + "\n";
            case "hostname":
                return InetAddress.getLocalHost().getHostName() + "\n";
            case "uname":
                return System.getProperty("os.name") + "\n";
            default:
                return null;
        }
    }

    private static String runLs(String[] parts) throws IOException {
        boolean longFormat = false;
        boolean showHidden = false;
        int i = 1;
        while (i < parts.length && parts[i].startsWith("-")) {
            String opt = parts[i];
            if (!LS_OPTIONS.contains(opt)) {
                return null;
            }
            if (opt.indexOf('l') >= 0) {
                longFormat = true;
            }
            if (opt.indexOf('a') >= 0) {
                showHidden = true;
            }
            i++;
        }
        String path = ".";
        if (i < parts.length) {
            if (i != parts.length - 1) {
                return null;
            }
            path = checkPath(parts[i]);
            if (path == null) {
                return null;
            }
        }
        return list(path, longFormat, showHidden);
    }

    /**
     * List a directory (equivalent of "ls -la").
     *
     * @return output, or null when the path is not allowed
     */
    public static String listDirectory(String path) throws IOException {
        String checked = checkPath(path);
        if (checked == null) {
            return null;
        }
        return list(checked, true, true);
    }

    /**
     * Fetch a host over the SSRF-validated HTTP client (equivalent of "curl host").
     *
     * @return the response body (capped), or null when the host is not allowed
     */
    public static String curlHost(String host) throws IOException {
        String checked = checkHost(host);
        if (checked == null) {
            return null;
        }
        HttpURLConnection conn;
        try {
            // validated (scheme, host, port, public address) and redirect-checked on every hop
            conn = HttpUtils.openValidatedConnection("http://" + checked + "/");
        } catch (IOException e) {
            return null;
        }
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8))) {
            StringBuilder sb = new StringBuilder();
            char[] buf = new char[4096];
            int n;
            while (sb.length() < MAX_OUTPUT_CHARS && (n = reader.read(buf)) != -1) {
                sb.append(buf, 0, Math.min(n, MAX_OUTPUT_CHARS - sb.length()));
            }
            return sb.toString();
        } finally {
            conn.disconnect();
        }
    }

    /** Allowed base directories (real paths): the working directory and the temp directory. */
    private static List<Path> allowedBases() {
        List<Path> bases = new ArrayList<>();
        String[] roots = {Paths.get("").toAbsolutePath().toString(), System.getProperty("java.io.tmpdir")};
        for (String root : roots) {
            if (root == null) {
                continue;
            }
            try {
                bases.add(Paths.get(root).toRealPath());
            } catch (IOException e) {
                // base does not exist: not usable
            }
        }
        return bases;
    }

    /**
     * Resolve the text to a real path (symlinks resolved) that lies under an allowed base.
     *
     * @return the confined real path, or null
     */
    private static Path confine(String text) {
        List<Path> bases = allowedBases();
        if (bases.isEmpty()) {
            return null;
        }
        Path requested = Paths.get(text);
        Path candidate = requested.isAbsolute() ? requested : bases.get(0).resolve(requested);
        // Pure path arithmetic against the (real) base directories: no filesystem existence/type check.
        Path normalized = candidate.normalize();
        for (Path base : bases) {
            if (normalized.startsWith(base)) {
                return rejectSymlinks(base, normalized);
            }
        }
        return null;
    }

    /**
     * Walk the components below base and read each one's attributes without following links; any
     * symbolic link (which could lead outside the allowed base) or unreadable component rejects
     * the path.
     *
     * @return the path when no component is a symbolic link, otherwise null
     */
    private static Path rejectSymlinks(Path base, Path normalized) {
        Path current = base;
        for (Path part : base.relativize(normalized)) {
            if (part.toString().isEmpty()) {
                continue;
            }
            current = current.resolve(part);
            try {
                BasicFileAttributes attrs = Files.readAttributes(current, BasicFileAttributes.class,
                        LinkOption.NOFOLLOW_LINKS);
                if (attrs.isSymbolicLink()) {
                    return null;
                }
            } catch (IOException e) {
                return null;
            }
        }
        return normalized;
    }

    private static String list(String text, boolean longFormat, boolean showHidden) throws IOException {
        Path dir = confine(text);
        if (dir == null) {
            return null;
        }
        StringBuilder sb = new StringBuilder();
        List<Path> entries = new ArrayList<>();
        // Single attempt to open the directory; no separate exists/isDirectory pre-check.
        try (DirectoryStream<Path> stream = Files.newDirectoryStream(dir)) {
            for (Path entry : stream) {
                if (entries.size() >= MAX_ENTRIES) {
                    break;
                }
                Path name = entry.getFileName();
                if (name == null || (!showHidden && name.toString().startsWith("."))) {
                    continue;
                }
                entries.add(entry);
            }
        } catch (NotDirectoryException e) {
            // A plain file: report the single entry (attributes are read once, without following links).
            appendEntry(sb, dir, dir.getFileName() == null ? dir.toString() : dir.getFileName().toString(),
                    longFormat);
            return sb.toString();
        } catch (IOException e) {
            return null;
        }
        Collections.sort(entries);
        for (Path entry : entries) {
            appendEntry(sb, entry, entry.getFileName().toString(), longFormat);
            if (sb.length() >= MAX_OUTPUT_CHARS) {
                break;
            }
        }
        return sb.toString();
    }

    private static void appendEntry(StringBuilder sb, Path entry, String name, boolean longFormat) {
        if (longFormat) {
            try {
                BasicFileAttributes attrs = Files.readAttributes(entry, BasicFileAttributes.class,
                        LinkOption.NOFOLLOW_LINKS);
                char type = attrs.isDirectory() ? 'd' : (attrs.isSymbolicLink() ? 'l' : '-');
                sb.append(type).append(' ').append(attrs.size()).append(' ')
                        .append(attrs.lastModifiedTime().toInstant()).append(' ');
            } catch (IOException e) {
                sb.append("? ");
            }
        }
        sb.append(name).append('\n');
    }
}
