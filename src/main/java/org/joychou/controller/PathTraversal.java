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
import java.nio.file.Paths;

@RestController
public class PathTraversal {

    protected final Logger logger = LoggerFactory.getLogger(this.getClass());

    // Base directory for serving images
    private static final String IMAGE_BASE_DIR = System.getProperty("user.dir");

    /**
     * http://localhost:8080/path_traversal/vul?filepath=example.jpg
     */
    @GetMapping("/path_traversal/vul")
    public String getImage(String filepath) throws IOException {
        if (filepath == null || filepath.contains("..")) {
            return "Bad boy. Illegal file path.";
        }
        String safePath = validateAndResolvePath(filepath);
        if (safePath == null) {
            return "Bad boy. Illegal file path.";
        }
        return getImgBase64(safePath);
    }

    @GetMapping("/path_traversal/sec")
    public String getImageSec(String filepath) throws IOException {
        if (SecurityUtil.pathFilter(filepath) == null) {
            logger.info("Illegal file path: " + filepath);
            return "Bad boy. Illegal file path.";
        }
        String safePath = validateAndResolvePath(filepath);
        if (safePath == null) {
            logger.info("Illegal file path: " + filepath);
            return "Bad boy. Illegal file path.";
        }
        return getImgBase64(safePath);
    }

    private String getImgBase64(String imgFile) throws IOException {

        logger.info("Working directory: " + System.getProperty("user.dir"));
        logger.info("File path: " + imgFile);

        File f = new File(imgFile);
        if (f.exists() && !f.isDirectory()) {
            byte[] data = Files.readAllBytes(f.toPath());
            return new String(Base64.encodeBase64(data));
        } else {
            return "File doesn't exist or is not a file.";
        }
    }

    /**
     * Resolve and validate the file path stays within the allowed base directory.
     *
     * @param filepath user-supplied relative file path
     * @return canonical path if valid, null if the path escapes the base directory
     */
    private String validateAndResolvePath(String filepath) {
        try {
            File baseDir = new File(IMAGE_BASE_DIR);
            File requestedFile = new File(baseDir, filepath);
            String canonicalBase = baseDir.getCanonicalPath();
            String canonicalPath = requestedFile.getCanonicalPath();
            if (!canonicalPath.startsWith(canonicalBase + File.separator) && !canonicalPath.equals(canonicalBase)) {
                return null;
            }
            return canonicalPath;
        } catch (IOException e) {
            logger.error("Error resolving file path: " + e.getMessage());
            return null;
        }
    }

    public static void main(String[] argv) throws IOException {
        String aa = new String(Files.readAllBytes(Paths.get("pom.xml")), StandardCharsets.UTF_8);
        System.out.println(aa);
    }
}