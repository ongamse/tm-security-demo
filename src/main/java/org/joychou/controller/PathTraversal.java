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
            logger.info("Illegal file path: " + filepath);
            return "Bad boy. Illegal file path.";
        }
        return getImgBase64(filepath);
    }

    private String getImgBase64(String imgFile) throws IOException {

        logger.info("Working directory: " + System.getProperty("user.dir"));
        logger.info("File path: " + imgFile);

        // Confine reads to the working directory: resolve, normalize and check containment
        // (also against symlink escapes) before touching the file.
        Path baseDir = Paths.get(System.getProperty("user.dir")).toRealPath();
        Path realPath;
        try {
            Path target = baseDir.resolve(imgFile).normalize();
            if (!target.startsWith(baseDir)) {
                return "Bad boy. Illegal file path.";
            }
            // Resolve the real path once (no separate exists/isDirectory check), then verify
            // containment on that resolved path and read through it only.
            realPath = target.toRealPath();
            if (!realPath.startsWith(baseDir)) {
                return "Bad boy. Illegal file path.";
            }
        } catch (InvalidPathException e) {
            return "Bad boy. Illegal file path.";
        } catch (NoSuchFileException e) {
            return "File doesn't exist or is not a file.";
        } catch (IOException e) {
            return "File doesn't exist or is not a file.";
        }

        // Single open+read on the resolved real path; symlinks are refused and a directory
        // or other non-readable entry surfaces as an IOException.
        try (InputStream in = Files.newInputStream(realPath, LinkOption.NOFOLLOW_LINKS)) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buffer = new byte[8192];
            int n;
            while ((n = in.read(buffer)) != -1) {
                out.write(buffer, 0, n);
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