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
            logger.info("Illegal file path rejected");
            return "Bad boy. Illegal file path.";
        }
        return getImgBase64(filepath);
    }

    private String getImgBase64(String imgFile) throws IOException {

        logger.info("Reading image file below the working directory");

        if (imgFile == null || imgFile.indexOf('\0') != -1) {
            return "File doesn't exist or is not a file.";
        }

        // Only files below the working directory may be read.
        Path baseDir = Paths.get(System.getProperty("user.dir")).toAbsolutePath().normalize();
        Path target;
        try {
            target = baseDir.resolve(imgFile).normalize();
        } catch (InvalidPathException e) {
            return "File doesn't exist or is not a file.";
        }
        if (!target.startsWith(baseDir) || target.equals(baseDir)) {
            logger.info("Illegal file path rejected");
            return "Bad boy. Illegal file path.";
        }

        // Read atomically (no exists()/isDirectory() pre-check); a missing file or a directory
        // surfaces as an IOException. Resolve symlinks once and re-verify containment.
        try {
            Path realBase = baseDir.toRealPath();
            Path realTarget = target.toRealPath();
            if (!realTarget.startsWith(realBase) || realTarget.equals(realBase)) {
                logger.info("Illegal file path rejected");
                return "Bad boy. Illegal file path.";
            }
            byte[] data = Files.readAllBytes(realTarget);
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