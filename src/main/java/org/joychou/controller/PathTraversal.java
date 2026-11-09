package org.joychou.controller;

import org.apache.commons.codec.binary.Base64;
import org.joychou.security.SecurityUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import org.springframework.util.StreamUtils;

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

        // Resolve against the fixed working directory, normalize ("..", "."), and enforce
        // base-directory containment on the real (symlink-free) parent directory.
        Path target;
        try {
            target = resolveInAllowedDir(imgFile);
        } catch (InvalidPathException e) {
            return "File doesn't exist or is not a file.";
        }
        if (target == null) {
            logger.info("File path outside of allowed directories: " + imgFile);
            return "Bad boy. Illegal file path.";
        }

        // Open the already-resolved path directly (no exists()/isFile() pre-check); the final
        // component is never followed if it is a symlink. Missing files and directories
        // surface as IOException.
        try (InputStream in = Files.newInputStream(target, LinkOption.NOFOLLOW_LINKS)) {
            byte[] data = StreamUtils.copyToByteArray(in);
            return new String(Base64.encodeBase64(data));
        } catch (IOException e) {
            return "File doesn't exist or is not a file.";
        }
    }

    /**
     * Only files under the working directory or the upload directory may be read.
     * Returns the normalized path (parent directory resolved to its real path) when it lies
     * inside an allowed base directory, or null when it does not.
     */
    private static Path resolveInAllowedDir(String requested) throws IOException {
        Path workDir = Paths.get(System.getProperty("user.dir")).toRealPath();
        Path resolved = workDir.resolve(requested).normalize();
        Path parent = resolved.getParent();
        Path name = resolved.getFileName();
        if (parent == null || name == null) {
            return null;
        }

        Path realParent;
        try {
            realParent = parent.toRealPath();
        } catch (IOException e) {
            // Parent directory does not exist: only report "not found" if it was lexically inside.
            return isUnderAllowedBase(resolved) ? parent.resolve(name) : null;
        }
        Path candidate = realParent.resolve(name);
        return isUnderAllowedBase(candidate) ? candidate : null;
    }

    private static boolean isUnderAllowedBase(Path path) {
        String[] allowedDirs = {System.getProperty("user.dir"), "/tmp"};
        for (String dir : allowedDirs) {
            try {
                Path base = Paths.get(dir).toRealPath();
                if (path.startsWith(base) && !path.equals(base)) {
                    return true;
                }
            } catch (IOException e) {
                // base directory unavailable; skip it
            }
        }
        return false;
    }

    public static void main(String[] argv) throws IOException {
        String aa = new String(Files.readAllBytes(Paths.get("pom.xml")), StandardCharsets.UTF_8);
        System.out.println(aa);
    }
}