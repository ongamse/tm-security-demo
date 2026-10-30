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

    // Allowed base directory for image files served by this controller
    private static final String IMAGE_BASE_DIR = System.getProperty("user.dir");

    /**
     * Resolve and validate that a file path is under the allowed base directory.
     *
     * @param filePath user-supplied file path
     * @return the validated canonical path
     * @throws IOException if the path escapes the allowed directory
     */
    private Path validatePath(String filePath) throws IOException {
        if (filePath == null || filePath.isEmpty()) {
            throw new IOException("File path must not be empty");
        }
        Path base = Paths.get(IMAGE_BASE_DIR).toAbsolutePath().normalize();
        Path resolved = base.resolve(filePath).toAbsolutePath().normalize();
        if (!resolved.startsWith(base)) {
            throw new IOException("Path traversal detected: path is outside allowed directory");
        }
        return resolved;
    }

    /**
     * http://localhost:8080/path_traversal/vul?filepath=../../../../../etc/passwd
     */
    @GetMapping("/path_traversal/vul")
    public String getImage(String filepath) throws IOException {
        try {
            Path validated = validatePath(filepath);
            return getImgBase64(validated);
        } catch (IOException e) {
            logger.info("Illegal file path: " + filepath);
            return "Bad boy. Illegal file path.";
        }
    }

    @GetMapping("/path_traversal/sec")
    public String getImageSec(String filepath) throws IOException {
        if (SecurityUtil.pathFilter(filepath) == null) {
            logger.info("Illegal file path: " + filepath);
            return "Bad boy. Illegal file path.";
        }
        try {
            Path validated = validatePath(filepath);
            return getImgBase64(validated);
        } catch (IOException e) {
            logger.info("Illegal file path: " + filepath);
            return "Bad boy. Illegal file path.";
        }
    }

    private String getImgBase64(Path validatedPath) throws IOException {

        logger.info("Working directory: " + System.getProperty("user.dir"));
        logger.info("File path: " + validatedPath);

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