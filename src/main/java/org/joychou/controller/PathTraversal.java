package org.joychou.controller;

import org.apache.commons.codec.binary.Base64;
import org.joychou.security.SecurityUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;

@RestController
public class PathTraversal {

    protected final Logger logger = LoggerFactory.getLogger(this.getClass());

    private static final int MAX_FILE_BYTES = 10 * 1024 * 1024;

    private static final Set<String> ALLOWED_EXTENSIONS =
            new HashSet<>(Arrays.asList("jpg", "jpeg", "png", "gif", "bmp"));

    /**
     * http://localhost:8080/path_traversal/vul?filepath=../../../../../etc/passwd
     */
    @GetMapping("/path_traversal/vul")
    public String getImage(String filepath) throws IOException {
        return readImageBase64(filepath);
    }

    @GetMapping("/path_traversal/sec")
    public String getImageSec(String filepath) throws IOException {
        if (filepath == null || SecurityUtil.pathFilter(filepath) == null) {
            logger.info("Illegal file path: {}", SecurityUtil.sanitizeForLog(filepath));
            return "Bad boy. Illegal file path.";
        }
        return readImageBase64(filepath);
    }

    /**
     * Resolve the request path against the base directory and read it. The only
     * Path handed to the I/O layer is the one returned by resolveInside.
     */
    private String readImageBase64(String userPath) throws IOException {
        logger.info("Working directory: " + System.getProperty("user.dir"));
        logger.info("File path: {}", SecurityUtil.sanitizeForLog(userPath));

        Path base = Paths.get(System.getProperty("user.dir")).toRealPath();
        Path verified = resolveInside(base, userPath);
        if (verified == null) {
            logger.info("Illegal file path: {}", SecurityUtil.sanitizeForLog(userPath));
            return "Bad boy. Illegal file path.";
        }
        return getImgBase64(verified);
    }

    /**
     * Resolve userPath under base. Rejects null/empty, NUL, backslash, absolute
     * paths and ".." segments; normalizes, resolves symlinks, then verifies the
     * result is still inside base and has an allowed image extension.
     *
     * @return the verified real path, or null if the path is not acceptable
     */
    private static Path resolveInside(Path base, String userPath) {
        if (base == null || userPath == null || userPath.isEmpty()
                || userPath.indexOf('\0') >= 0 || userPath.indexOf('\\') >= 0
                || userPath.charAt(0) == '/') {
            return null;
        }
        for (String segment : userPath.split("/", -1)) {
            if ("..".equals(segment)) {
                return null;
            }
        }
        try {
            Path normalized = base.resolve(userPath).normalize();
            if (!normalized.startsWith(base)) {
                return null;
            }
            Path real = normalized.toRealPath();
            if (!real.startsWith(base)) {
                return null;
            }
            Path fileName = real.getFileName();
            if (fileName == null) {
                return null;
            }
            String name = fileName.toString().toLowerCase(Locale.ROOT);
            int dot = name.lastIndexOf('.');
            String ext = dot < 0 ? "" : name.substring(dot + 1);
            if (!ALLOWED_EXTENSIONS.contains(ext)) {
                return null;
            }
            return real;
        } catch (IOException | InvalidPathException e) {
            return null;
        }
    }

    private String getImgBase64(Path target) throws IOException {

        // Open once and read from the handle (no separate check step on the path).
        // A missing file or a directory surfaces as an IOException here.
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (InputStream in = Files.newInputStream(target, LinkOption.NOFOLLOW_LINKS)) {
            byte[] buf = new byte[8192];
            int n;
            while ((n = in.read(buf)) != -1) {
                if (out.size() + n > MAX_FILE_BYTES) {
                    return "File is too large.";
                }
                out.write(buf, 0, n);
            }
        } catch (IOException e) {
            return "File doesn't exist or is not a file.";
        }
        return new String(Base64.encodeBase64(out.toByteArray()));
    }

    public static void main(String[] argv) throws IOException {
        String aa = new String(Files.readAllBytes(Paths.get("pom.xml")), StandardCharsets.UTF_8);
        System.out.println(aa);
    }
}