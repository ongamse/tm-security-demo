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

    protected final Logger logger = LoggerFactory.getLogger(this.getClass());

    private static final int MAX_FILE_BYTES = 10 * 1024 * 1024;

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
            logger.info("Illegal file path: {}", SecurityUtil.sanitizeForLog(filepath));
            return "Bad boy. Illegal file path.";
        }
        return getImgBase64(filepath);
    }

    private String getImgBase64(String imgFile) throws IOException {

        logger.info("Working directory: " + System.getProperty("user.dir"));
        logger.info("File path: {}", SecurityUtil.sanitizeForLog(imgFile));

        if (imgFile == null) {
            return "File doesn't exist or is not a file.";
        }

        // Canonicalize and make sure the file stays inside the working directory.
        Path base = Paths.get(System.getProperty("user.dir")).toRealPath();
        Path target;
        try {
            target = base.resolve(imgFile).toRealPath();
        } catch (IOException | InvalidPathException e) {
            return "File doesn't exist or is not a file.";
        }
        if (!target.startsWith(base)) {
            logger.info("Illegal file path: {}", SecurityUtil.sanitizeForLog(imgFile));
            return "Bad boy. Illegal file path.";
        }

        // Open once and read from the handle (no separate check step on the path).
        // A missing file or a directory surfaces as an IOException here.
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (InputStream in = Files.newInputStream(target, LinkOption.NOFOLLOW_LINKS)) {
            byte[] buf = new byte[8192];
            int n;
            while ((n = in.read(buf)) != -1) {
                if (out.size() + n > MAX_FILE_BYTES) {
                    return "File is too large.";
                }
                out.write(buf, 0, n);
            }
        } catch (IOException e) {
            return "File doesn't exist or is not a file.";
        }
        return new String(Base64.encodeBase64(out.toByteArray()));
    }

    public static void main(String[] argv) throws IOException {
        String aa = new String(Files.readAllBytes(Paths.get("pom.xml")), StandardCharsets.UTF_8);
        System.out.println(aa);
    }
}