package org.joychou.controller;

import org.springframework.web.util.HtmlUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.NotDirectoryException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.regex.Pattern;

@RestController
public class CommandInject {

    protected final Logger logger = LoggerFactory.getLogger(this.getClass());

    private static final Pattern HOST_PATTERN = Pattern.compile("^[a-zA-Z0-9][a-zA-Z0-9.-]*(:[0-9]{1,5})?$");

    /**
     * Fixed base directory; only directories inside it can be listed.
     */
    private static final Path BASE_DIR = Paths.get(System.getProperty("java.io.tmpdir"))
            .toAbsolutePath().normalize();

    /**
     * http://localhost:8080/codeinject?filepath=/tmp
     *
     * @param filepath filepath
     * @return result
     */
    @GetMapping("/codeinject")
    public String codeInject(String filepath) throws IOException {
        return listDirectory(filepath);
    }

    /**
     * Host Injection
     * http://localhost:8080/codeinject/host
     */
    @GetMapping("/codeinject/host")
    public String codeInjectHost(HttpServletRequest request) {

        String host = request.getHeader("host");
        if (null == host || !HOST_PATTERN.matcher(host).matches()) {
            return "Bad boy. I got u.";
        }
        // No process is started; the validated host is only echoed back, escaped.
        return HtmlUtils.htmlEscape(host);
    }

    @GetMapping("/codeinject/sec")
    public String codeInjectSec(String filepath) throws IOException {
        return listDirectory(filepath);
    }

    /**
     * Pure Java directory listing confined to BASE_DIR. No process is started.
     */
    private static String listDirectory(String filepath) throws IOException {
        if (null == filepath || filepath.indexOf('\0') >= 0) {
            return "Bad boy. I got u.";
        }
        Path target;
        try {
            target = BASE_DIR.resolve(filepath).normalize();
        } catch (java.nio.file.InvalidPathException e) {
            return "Bad boy. I got u.";
        }
        if (!target.startsWith(BASE_DIR)) {
            return "Bad boy. I got u.";
        }
        List<String> names = new ArrayList<>();
        try {
            // Resolve symlinks so a link inside the base cannot escape it.
            Path realTarget = target.toRealPath();
            if (!realTarget.startsWith(BASE_DIR.toRealPath())) {
                return "Bad boy. I got u.";
            }
            try (DirectoryStream<Path> stream = Files.newDirectoryStream(realTarget)) {
                for (Path p : stream) {
                    names.add(p.getFileName().toString());
                }
            }
        } catch (NotDirectoryException | NoSuchFileException e) {
            return "Bad boy. I got u.";
        } catch (IOException e) {
            return "Bad boy. I got u.";
        }
        Collections.sort(names);
        return HtmlUtils.htmlEscape(String.join("\n", names));
    }
}
