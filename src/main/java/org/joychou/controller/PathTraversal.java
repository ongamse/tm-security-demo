package org.joychou.controller;

import org.apache.commons.codec.binary.Base64;
import org.joychou.security.SecurityUtil;
import org.joychou.util.LogSanitizer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.Paths;

@RestController
public class PathTraversal {

    protected final Logger logger = LoggerFactory.getLogger(this.getClass());

    /**
     * http://localhost:8080/path_traversal/vul?filepath=../../../../../etc/passwd
     */
    @GetMapping("/path_traversal/vul")
    public String getImage(String filepath) throws IOException {
        return getImgBase64(filepath);
    }

    @GetMapping("/path_traversal/sec")
    public String getImageSec(String filepath) throws IOException {
        if (SecurityUtil.pathFilter(filepath) == null) {
            logger.info("Illegal file path: {}", LogSanitizer.clean(filepath));
            return "Bad boy. Illegal file path.";
        }
        return getImgBase64(filepath);
    }

    private String getImgBase64(String imgFile) throws IOException {

        logger.info("Working directory: {}", LogSanitizer.clean(System.getProperty("user.dir")));
        logger.info("File path: {}", LogSanitizer.clean(imgFile));

        Path safePath = resolveInBaseDir(imgFile);
        if (safePath == null) {
            return "Bad boy. Illegal file path.";
        }
        // Read directly (no check-then-read) and handle the failure.
        try {
            byte[] data = Files.readAllBytes(safePath);
            return new String(Base64.encodeBase64(data));
        } catch (IOException e) {
            logger.info("Cannot read file: " + e.getClass().getSimpleName());
            return "File doesn't exist or is not a file.";
        }
    }

    /**
     * Resolve a client supplied path against the working directory and make sure
     * the real (symlink-resolved) path stays inside it.
     *
     * @return the contained real path, or null if the path is illegal or escapes the base directory
     */
    private static Path resolveInBaseDir(String userPath) throws IOException {
        if (userPath == null || userPath.isEmpty() || userPath.indexOf('\0') >= 0) {
            return null;
        }
        Path base = Paths.get(System.getProperty("user.dir")).toRealPath();
        Path resolved;
        try {
            resolved = base.resolve(userPath).normalize();
        } catch (InvalidPathException e) {
            return null;
        }
        if (!resolved.startsWith(base)) {
            return null;
        }
        Path real;
        try {
            real = resolved.toRealPath();
        } catch (NoSuchFileException e) {
            // Does not exist: lexically confined path; the caller's read will fail cleanly.
            return resolved;
        }
        return real.startsWith(base) ? real : null;
    }

    public static void main(String[] argv) throws IOException {
        String aa = new String(Files.readAllBytes(Paths.get("pom.xml")), StandardCharsets.UTF_8);
        System.out.println(aa);
    }
}