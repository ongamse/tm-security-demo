package org.joychou.controller;

import org.apache.commons.codec.binary.Base64;
import org.joychou.security.LogSafe;
import org.joychou.security.SecurityUtil;
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
            logger.info("Illegal file path: {}", LogSafe.fingerprint(filepath));
            return "Bad boy. Illegal file path.";
        }
        return getImgBase64(filepath);
    }

    private String getImgBase64(String imgFile) throws IOException {

        logger.info("Working directory: " + System.getProperty("user.dir"));
        logger.info("File path: {}", LogSafe.fingerprint(imgFile));

        if (imgFile == null) {
            return "File doesn't exist or is not a file.";
        }

        // Resolve against the working directory and reject anything that escapes it.
        Path base = Paths.get(System.getProperty("user.dir")).toAbsolutePath().normalize();
        Path safePath;
        try {
            safePath = base.resolve(imgFile).normalize();
            if (!safePath.startsWith(base)) {
                logger.info("Illegal file path: {}", LogSafe.fingerprint(imgFile));
                return "Bad boy. Illegal file path.";
            }
        } catch (InvalidPathException e) {
            return "Bad boy. Illegal file path.";
        }

        try {
            // Resolve symlinks too, so a link inside the base cannot point outside it.
            // Read directly (no separate exists()/isDirectory() check) to avoid a check-then-use race.
            Path realPath = safePath.toRealPath();
            if (!realPath.startsWith(base.toRealPath())) {
                logger.info("Illegal file path: {}", LogSafe.fingerprint(imgFile));
                return "Bad boy. Illegal file path.";
            }
            byte[] data = Files.readAllBytes(realPath);
            return new String(Base64.encodeBase64(data));
        } catch (NoSuchFileException e) {
            return "File doesn't exist or is not a file.";
        } catch (IOException e) {
            // Includes attempts to read a directory or an unreadable file.
            logger.info("file operation failed: {}", LogSafe.errorName(e));
            return "File doesn't exist or is not a file.";
        }
    }

    public static void main(String[] argv) throws IOException {
        String aa = new String(Files.readAllBytes(Paths.get("pom.xml")), StandardCharsets.UTF_8);
        System.out.println(aa);
    }
}