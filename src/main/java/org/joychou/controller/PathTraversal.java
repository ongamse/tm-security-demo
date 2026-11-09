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

    private String getImgBase64(String imgFile) throws IOException {

        logger.info("Working directory: " + System.getProperty("user.dir"));
        logger.info("File path: " + imgFile);

        if (imgFile == null || imgFile.indexOf('\0') != -1) {
            return "File doesn't exist or is not a file.";
        }

        // Canonicalize (resolves "..", "." and symlinks) and enforce base-directory containment.
        File f = new File(imgFile).getCanonicalFile();
        if (!isInAllowedDir(f)) {
            logger.info("File path outside of allowed directories: " + imgFile);
            return "Bad boy. Illegal file path.";
        }
        if (f.exists() && !f.isDirectory()) {
            byte[] data = Files.readAllBytes(f.toPath());
            return new String(Base64.encodeBase64(data));
        } else {
            return "File doesn't exist or is not a file.";
        }
    }

    /**
     * Only files under the working directory or the upload directory may be read.
     */
    private static boolean isInAllowedDir(File canonicalFile) throws IOException {
        String[] allowedDirs = {System.getProperty("user.dir"), "/tmp"};
        for (String dir : allowedDirs) {
            Path base = new File(dir).getCanonicalFile().toPath();
            if (canonicalFile.toPath().startsWith(base)) {
                return true;
            }
        }
        return false;
    }

    public static void main(String[] argv) throws IOException {
        String aa = new String(Files.readAllBytes(Paths.get("pom.xml")), StandardCharsets.UTF_8);
        System.out.println(aa);
    }
}