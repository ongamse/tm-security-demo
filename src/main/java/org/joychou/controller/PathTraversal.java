package org.joychou.controller;

import org.apache.commons.codec.binary.Base64;
import org.joychou.security.SecurityUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.Paths;

@RestController
public class PathTraversal {

    protected final Logger logger = LoggerFactory.getLogger(this.getClass());

    // Base directory for serving images
    private static final String BASE_IMAGE_DIR = System.getProperty("user.dir");

    /**
     * http://localhost:8080/path_traversal/vul?filepath=../../../../../etc/passwd
     */
    @GetMapping("/path_traversal/vul")
    public String getImage(String filepath) throws IOException {
        Path safePath = resolveAndValidatePath(filepath);
        if (safePath == null) {
            return "Bad boy. Illegal file path.";
        }
        return getImgBase64(safePath);
    }

    @GetMapping("/path_traversal/sec")
    public String getImageSec(String filepath) throws IOException {
        if (SecurityUtil.pathFilter(filepath) == null) {
            logger.info("Illegal file path: " + SecurityUtil.sanitizeForLog(filepath));
            return "Bad boy. Illegal file path.";
        }
        Path safePath = resolveAndValidatePath(filepath);
        if (safePath == null) {
            return "Bad boy. Illegal file path.";
        }
        return getImgBase64(safePath);
    }

    /**
     * Resolve and validate filepath against the base directory to prevent path traversal.
     */
    private Path resolveAndValidatePath(String filepath) {
        if (filepath == null || filepath.isEmpty()) {
            return null;
        }
        Path basePath = Paths.get(BASE_IMAGE_DIR).toAbsolutePath().normalize();
        Path resolved = basePath.resolve(filepath).normalize();
        if (!resolved.startsWith(basePath)) {
            logger.info("Path traversal detected: " + SecurityUtil.sanitizeForLog(filepath));
            return null;
        }
        return resolved;
    }

    private String getImgBase64(Path safePath) throws IOException {

        logger.info("Working directory: " + System.getProperty("user.dir"));
        logger.info("File path: " + SecurityUtil.sanitizeForLog(safePath.toString()));

        // Read directly without check-then-act to avoid TOCTOU race condition
        try {
            if (Files.isDirectory(safePath)) {
                return "File doesn't exist or is not a file.";
            }
            byte[] data = Files.readAllBytes(safePath);
            return new String(Base64.encodeBase64(data));
        } catch (NoSuchFileException e) {
            return "File doesn't exist or is not a file.";
        }
    }

    public static void main(String[] argv) throws IOException {
        String aa = new String(Files.readAllBytes(Paths.get("pom.xml")), StandardCharsets.UTF_8);
        System.out.println(aa);
    }
}