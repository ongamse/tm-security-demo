package org.joychou.security;

import java.io.IOException;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Locale;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Pattern;

/**
 * Shared control for stored upload paths.
 *
 * The client supplied file name is never used to build a File/Path. The stored
 * name is generated server side (random UUID + an extension taken from a fixed
 * allowlist) and resolved against a fixed, canonical upload base directory.
 */
public final class UploadPaths {

    private static final Pattern EXTENSION_FORMAT = Pattern.compile("[A-Za-z0-9]{1,8}");

    private UploadPaths() {
    }

    /**
     * Pick the extension for a client supplied file name from a fixed allowlist.
     *
     * @param originalName client supplied name (only inspected, never used in a path)
     * @param allowlist    lower-case extensions without dot
     * @return the matching allowlist constant (not the client string), or null when rejected
     */
    public static String allowedExtension(String originalName, Set<String> allowlist) {
        if (originalName == null) {
            return null;
        }
        int dot = originalName.lastIndexOf('.');
        if (dot < 0 || dot == originalName.length() - 1) {
            return null;
        }
        String candidate = originalName.substring(dot + 1);
        if (!EXTENSION_FORMAT.matcher(candidate).matches()) {
            return null;
        }
        String lower = candidate.toLowerCase(Locale.ROOT);
        for (String allowed : allowlist) {
            if (allowed.equals(lower) && EXTENSION_FORMAT.matcher(allowed).matches()) {
                return allowed;
            }
        }
        return null;
    }

    /**
     * Build a new server generated path (UUID + allowlisted extension) inside the upload base.
     * Fails closed when the result is not a direct child of the canonical base directory.
     */
    public static Path newUploadPath(String baseDir, String allowedExtension) throws IOException {
        if (allowedExtension == null || !EXTENSION_FORMAT.matcher(allowedExtension).matches()) {
            throw new IOException("Invalid file extension");
        }
        try {
            Path base = Paths.get(baseDir).toRealPath();
            Path target = base.resolve(UUID.randomUUID() + "." + allowedExtension).normalize();
            if (!target.startsWith(base) || !base.equals(target.getParent())) {
                throw new IOException("Invalid upload path");
            }
            return target;
        } catch (InvalidPathException e) {
            throw new IOException("Invalid upload path", e);
        }
    }
}
