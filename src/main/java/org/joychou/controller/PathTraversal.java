package org.joychou.controller;

import org.joychou.security.LogSanitizer;
import org.apache.commons.codec.binary.Base64;
import org.joychou.security.SecurityUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

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
            logger.info("Illegal file path: {}", LogSanitizer.clean(filepath));
            return "Bad boy. Illegal file path.";
        }
        return getImgBase64(filepath);
    }

    private String getImgBase64(String imgFile) throws IOException {

        logger.info("Working directory: {}", LogSanitizer.clean(System.getProperty("user.dir")));
        logger.info("File path: {}", LogSanitizer.clean(imgFile));

        if (imgFile == null || imgFile.indexOf('\0') != -1) {
            return "File doesn't exist or is not a file.";
        }

        // Only allow files located inside the working directory.
        Path base = Paths.get(System.getProperty("user.dir")).toAbsolutePath().normalize();
        Path target = base.resolve(imgFile).normalize();
        if (!target.startsWith(base)) {
            logger.info("Illegal file path outside of working directory");
            return "Bad boy. Illegal file path.";
        }

        // Read directly instead of check-then-read; a missing file or a directory raises IOException.
        try {
            byte[] data = Files.readAllBytes(target);
            return new String(Base64.encodeBase64(data));
        } catch (IOException e) {
            return "File doesn't exist or is not a file.";
        }
    }

    public static void main(String[] argv) throws IOException {
        String aa = new String(Files.readAllBytes(Paths.get("pom.xml")), StandardCharsets.UTF_8);
        System.out.println(aa);
    }
}