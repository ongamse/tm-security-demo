package org.joychou.controller;

import org.apache.commons.codec.binary.Base64;
import org.joychou.security.SecurityUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.Paths;

@RestController
public class PathTraversal {

    private static final int MAX_IMAGE_BYTES = 10 * 1024 * 1024;

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
            logger.info("Illegal file path.");
            return "Bad boy. Illegal file path.";
        }
        return getImgBase64(filepath);
    }

    private String getImgBase64(String imgFile) throws IOException {

        logger.info("Working directory: " + System.getProperty("user.dir"));

        if (imgFile == null) {
            return "File doesn't exist or is not a file.";
        }

        // Confine reads to the base directory (resolve, normalize, verify prefix, resolve symlinks).
        Path base = Paths.get(System.getProperty("user.dir")).toRealPath();
        Path target;
        try {
            target = base.resolve(imgFile).normalize();
        } catch (InvalidPathException e) {
            return "Bad boy. Illegal file path.";
        }
        if (!target.startsWith(base)) {
            logger.info("Illegal file path.");
            return "Bad boy. Illegal file path.";
        }

        // No separate existence/type check: resolve and read in one guarded operation.
        // NoSuchFileException, AccessDeniedException and "is a directory" read failures are all IOExceptions.
        try {
            Path realTarget = target.toRealPath();
            if (!realTarget.startsWith(base)) {
                logger.info("Illegal file path.");
                return "Bad boy. Illegal file path.";
            }

            ByteArrayOutputStream out = new ByteArrayOutputStream();
            try (InputStream in = Files.newInputStream(realTarget, LinkOption.NOFOLLOW_LINKS)) {
                byte[] buf = new byte[8192];
                int total = 0;
                int n;
                while ((n = in.read(buf)) != -1) {
                    total += n;
                    if (total > MAX_IMAGE_BYTES) {
                        return "File doesn't exist or is not a file.";
                    }
                    out.write(buf, 0, n);
                }
            }
            return new String(Base64.encodeBase64(out.toByteArray()));
        } catch (IOException e) {
            return "File doesn't exist or is not a file.";
        }
    }

    public static void main(String[] argv) throws IOException {
        String aa = new String(Files.readAllBytes(Paths.get("pom.xml")), StandardCharsets.UTF_8);
        System.out.println(aa);
    }
}