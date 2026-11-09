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
import java.util.Arrays;
import java.util.HashSet;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Stream;

@RestController
public class PathTraversal {

    protected final Logger logger = LoggerFactory.getLogger(this.getClass());

    private static final Set<String> ALLOWED_IMAGE_EXTENSIONS =
            new HashSet<>(Arrays.asList("png", "jpg", "jpeg", "gif", "bmp", "webp"));

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
            logger.info("Illegal file path rejected by pathFilter");
            return "Bad boy. Illegal file path.";
        }
        return getImgBase64(filepath);
    }

    private String getImgBase64(String imgFile) throws IOException {

        logger.info("Reading image file as base64");

        if (imgFile == null || imgFile.indexOf('\0') != -1) {
            return "File doesn't exist or is not a file.";
        }

        // Only a plain file name (no separators, no "." / "..") with an image extension is accepted.
        if (!isAllowedImageName(imgFile)) {
            logger.info("File path outside of allowed directories");
            return "Bad boy. Illegal file path.";
        }

        // The Path that is opened comes from listing a fixed server-side directory, never from
        // request text. Only direct children of the base directory can match the requested name.
        Path target = findInAllowedDirs(imgFile);
        if (target == null) {
            return "File doesn't exist or is not a file.";
        }

        // The final component is never followed if it is a symlink. Directories surface as
        // IOException.
        try (InputStream in = Files.newInputStream(target, LinkOption.NOFOLLOW_LINKS)) {
            byte[] data = StreamUtils.copyToByteArray(in);
            return new String(Base64.encodeBase64(data));
        } catch (IOException e) {
            return "File doesn't exist or is not a file.";
        }
    }

    private static boolean isAllowedImageName(String name) {
        if (name.isEmpty() || name.indexOf('/') != -1 || name.indexOf('\\') != -1
                || name.equals(".") || name.equals("..")) {
            return false;
        }
        int dot = name.lastIndexOf('.');
        if (dot <= 0) {
            return false;
        }
        String ext = name.substring(dot + 1).toLowerCase(Locale.ROOT);
        return ALLOWED_IMAGE_EXTENSIONS.contains(ext);
    }

    /**
     * Lists each allowed base directory (server-side constants) and returns the directory entry
     * whose file name equals the requested name, or null when there is none.
     */
    private static Path findInAllowedDirs(String name) {
        String[] allowedDirs = {System.getProperty("user.dir"), "/tmp"};
        for (String dir : allowedDirs) {
            try (Stream<Path> entries = Files.list(Paths.get(dir).toRealPath())) {
                Optional<Path> match = entries
                        .filter(p -> p.getFileName() != null && p.getFileName().toString().equals(name))
                        .findFirst();
                if (match.isPresent()) {
                    return match.get();
                }
            } catch (IOException | InvalidPathException e) {
                // base directory unavailable; skip it
            }
        }
        return null;
    }

    public static void main(String[] argv) throws IOException {
        String aa = new String(Files.readAllBytes(Paths.get("pom.xml")), StandardCharsets.UTF_8);
        System.out.println(aa);
    }
}