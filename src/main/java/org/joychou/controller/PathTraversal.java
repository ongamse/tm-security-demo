package org.joychou.controller;

import org.apache.commons.codec.binary.Base64;
import org.joychou.security.SecurityUtil;
import org.joychou.util.WebUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
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
            logger.info("Illegal file path: " + WebUtils.sanitizeLog(filepath));
            return "Bad boy. Illegal file path.";
        }
        return getImgBase64(filepath);
    }

    private String getImgBase64(String imgFile) throws IOException {

        logger.info("Working directory: " + System.getProperty("user.dir"));
        logger.info("File path: " + WebUtils.sanitizeLog(imgFile));

        if (imgFile == null) {
            return "File doesn't exist or is not a file.";
        }

        // Resolve against the working directory and reject anything that escapes it
        Path base = Paths.get(System.getProperty("user.dir")).toRealPath();
        Path target;
        try {
            target = base.resolve(imgFile).normalize();
            if (!target.startsWith(base)) {
                logger.info("Illegal file path: " + WebUtils.sanitizeLog(imgFile));
                return "Bad boy. Illegal file path.";
            }
            if (Files.exists(target)) {
                target = target.toRealPath();
                if (!target.startsWith(base)) {
                    logger.info("Illegal file path: " + WebUtils.sanitizeLog(imgFile));
                    return "Bad boy. Illegal file path.";
                }
            }
        } catch (InvalidPathException e) {
            return "Bad boy. Illegal file path.";
        }

        if (Files.exists(target) && !Files.isDirectory(target)) {
            byte[] data = Files.readAllBytes(target);
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