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
            logger.info("Illegal file path rejected by filter");
            return "Bad boy. Illegal file path.";
        }
        return getImgBase64(filepath);
    }

    private String getImgBase64(String imgFile) throws IOException {

        logger.info("Working directory: " + System.getProperty("user.dir"));
        logger.info("File path requested, length: {}", imgFile == null ? 0 : imgFile.length());

        if (imgFile == null || imgFile.isEmpty()) {
            return "File doesn't exist or is not a file.";
        }

        // Only serve files located below the working directory (canonicalized, symlinks resolved).
        Path base = Paths.get(System.getProperty("user.dir")).toRealPath();
        Path target;
        try {
            target = base.resolve(imgFile).normalize();
            if (!target.startsWith(base)) {
                logger.info("Illegal file path rejected: outside working directory");
                return "Bad boy. Illegal file path.";
            }
            // Resolves symlinks; throws NoSuchFileException if the file is missing.
            target = target.toRealPath();
            if (!target.startsWith(base)) {
                logger.info("Illegal file path rejected: resolves outside working directory");
                return "Bad boy. Illegal file path.";
            }
        } catch (InvalidPathException | NoSuchFileException e) {
            return "File doesn't exist or is not a file.";
        }

        // Single open+read of the contained path; failure (missing file, directory,
        // unreadable) is handled from this one operation instead of a prior check.
        try (InputStream in = Files.newInputStream(target, LinkOption.NOFOLLOW_LINKS)) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buf = new byte[8192];
            int n;
            while ((n = in.read(buf)) != -1) {
                out.write(buf, 0, n);
            }
            return new String(Base64.encodeBase64(out.toByteArray()));
        } catch (IOException e) {
            logger.info("File could not be read: {}", e.getClass().getSimpleName());
            return "File doesn't exist or is not a file.";
        }
    }

    public static void main(String[] argv) throws IOException {
        String aa = new String(Files.readAllBytes(Paths.get("pom.xml")), StandardCharsets.UTF_8);
        System.out.println(aa);
    }
}