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
import java.nio.file.Path;
import java.nio.file.Paths;

@RestController
public class PathTraversal {

    protected final Logger logger = LoggerFactory.getLogger(this.getClass());

    // Upper bound on the number of bytes read for a single image request (10 MB).
    private static final long MAX_IMAGE_BYTES = 10L * 1024 * 1024;

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

        logger.info("Image file requested");

        if (imgFile == null) {
            return "File doesn't exist or is not a file.";
        }

        // Resolve against the working directory and reject anything that escapes it.
        Path base = Paths.get(System.getProperty("user.dir")).toRealPath();
        Path real;
        try {
            Path target = base.resolve(imgFile).normalize();
            if (!target.startsWith(base)) {
                logger.info("Illegal file path rejected");
                return "Bad boy. Illegal file path.";
            }
            // No separate existence check: toRealPath fails if the file is missing.
            real = target.toRealPath();
            if (!real.startsWith(base)) {
                logger.info("Illegal file path rejected");
                return "Bad boy. Illegal file path.";
            }
        } catch (InvalidPathException e) {
            return "Bad boy. Illegal file path.";
        } catch (IOException e) {
            return "File doesn't exist or is not a file.";
        }

        // Open once and read from the handle; opening a directory or a missing file fails here.
        try (InputStream in = Files.newInputStream(real)) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buf = new byte[8192];
            long total = 0;
            int n;
            while ((n = in.read(buf)) != -1) {
                total += n;
                if (total > MAX_IMAGE_BYTES) {
                    return "File doesn't exist or is not a file.";
                }
                out.write(buf, 0, n);
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