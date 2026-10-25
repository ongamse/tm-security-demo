package org.joychou.controller;

import org.apache.commons.codec.binary.Base64;
import org.joychou.security.SecurityUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

@RestController
public class PathTraversal {

    protected final Logger logger = LoggerFactory.getLogger(this.getClass());

    // Allowed base directory for serving files
    private static final String SAFE_BASE_DIR = System.getProperty("user.dir");

    /**
     * Resolve and validate a file path against the safe base directory.
     * Rejects path traversal attempts (e.g., ../ sequences, absolute paths
     * that escape the base directory).
     *
     * @param filepath the user-supplied file path
     * @return the validated canonical Path, or null if the path is illegal
     */
    private Path safePath(String filepath) {
        if (filepath == null || filepath.isEmpty()) {
            return null;
        }
        Path base = Paths.get(SAFE_BASE_DIR).toAbsolutePath().normalize();
        Path resolved = base.resolve(filepath).normalize();
        if (!resolved.startsWith(base)) {
            return null;
        }
        return resolved;
    }

    /**
     * http://localhost:8080/path_traversal/vul?filepath=../../../../../etc/passwd
     */
    @GetMapping("/path_traversal/vul")
    public String getImage(String filepath) throws IOException {
        Path safe = safePath(filepath);
        if (safe == null) {
            logger.info("Illegal file path: " + filepath);
            return "Bad boy. Illegal file path.";
        }
        return getImgBase64(safe);
    }

    @GetMapping("/path_traversal/sec")
    public String getImageSec(String filepath) throws IOException {
        if (SecurityUtil.pathFilter(filepath) == null) {
            logger.info("Illegal file path: " + filepath);
            return "Bad boy. Illegal file path.";
        }
        Path safe = safePath(filepath);
        if (safe == null) {
            logger.info("Illegal file path: " + filepath);
            return "Bad boy. Illegal file path.";
        }
        return getImgBase64(safe);
    }

    private String getImgBase64(Path validatedPath) throws IOException {

        logger.info("Working directory: " + System.getProperty("user.dir"));
        logger.info("File path: " + validatedPath.toString());

        File f = validatedPath.toFile();
        if (f.exists() && !f.isDirectory()) {
            byte[] data = Files.readAllBytes(validatedPath);
            return new String(Base64.encodeBase64(data));
        } else {
            return "File doesn't exist or is not a file.";
        }
    }

    public static void main(String[] argv) throws IOException {
        String aa = new String(Files.readAllBytes(Paths.get("pom.xml")), StandardCharsets.UTF_8);
        System.out.println(aa);
    }
}