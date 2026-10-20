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
            logger.info("Illegal file path: " + filepath);
            return "Bad boy. Illegal file path.";
        }
        return getImgBase64(filepath);
    }

    // Base directory for serving images
    private static final String IMAGE_BASE_DIR = System.getProperty("user.dir");

    private String getImgBase64(String imgFile) throws IOException {

        logger.info("Working directory: " + System.getProperty("user.dir"));
        logger.info("File path: " + imgFile);

        // Reject absolute paths and traversal sequences before resolving
        if (imgFile == null || imgFile.isEmpty() || imgFile.startsWith("/") || imgFile.contains("..")) {
            logger.error("Path traversal attempt blocked: " + imgFile);
            return "Bad boy. Illegal file path.";
        }
        // Canonicalize and verify the resolved path stays within the base directory
        java.nio.file.Path basePath = Paths.get(IMAGE_BASE_DIR).toAbsolutePath().normalize();
        java.nio.file.Path resolvedPath = basePath.resolve(imgFile).toAbsolutePath().normalize();
        if (!resolvedPath.startsWith(basePath)) {
            logger.error("Path traversal attempt blocked: " + imgFile);
            return "Bad boy. Illegal file path.";
        }

        File f = resolvedPath.toFile();
        if (f.exists() && !f.isDirectory()) {
            byte[] data = Files.readAllBytes(resolvedPath);
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