package org.joychou.controller;

import org.springframework.web.util.HtmlUtils;
import org.joychou.security.SecurityUtil;
import org.joychou.security.ssrf.SSRFChecker;
import org.joychou.util.HttpUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.regex.Pattern;

@RestController
public class CommandInject {

    private static final Pattern HOST_PATTERN = Pattern.compile("^[a-zA-Z0-9][a-zA-Z0-9.-]*(:[0-9]{1,5})?$");

    /** Directory listings are confined to this fixed base directory. */
    private static final String BASE_DIR = "/tmp";

    protected final Logger logger = LoggerFactory.getLogger(this.getClass());

    /**
     * List a directory without spawning a process. The requested path must stay under BASE_DIR.
     */
    private String listDirectory(String filepath) {
        String safePath = SecurityUtil.cmdFilter(filepath);
        if (null == safePath) {
            return "Bad boy. I got u.";
        }
        List<String> names = new ArrayList<String>();
        try {
            Path base = Paths.get(BASE_DIR).toRealPath();
            Path target = base.resolve(safePath).normalize();
            if (!target.startsWith(base)) {
                return "Bad boy. I got u.";
            }
            // Single open operation: no exists/isDirectory pre-check. A missing path or a
            // non-directory makes the open itself fail (NoSuchFileException / NotDirectoryException).
            try (DirectoryStream<Path> stream = Files.newDirectoryStream(target)) {
                // Symlink containment is verified on the opened directory before anything is listed.
                if (!target.toRealPath().startsWith(base)) {
                    return "Bad boy. I got u.";
                }
                for (Path entry : stream) {
                    names.add(entry.getFileName().toString());
                }
            }
        } catch (IOException e) {
            logger.error("Directory listing failed", e);
            return "Bad boy. I got u.";
        }
        Collections.sort(names);
        StringBuilder sb = new StringBuilder();
        for (String name : names) {
            sb.append(name).append('\n');
        }
        return HtmlUtils.htmlEscape(sb.toString());
    }

    /**
     * http://localhost:8080/codeinject?filepath=/tmp;cat /etc/passwd
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
     * Host: hacked by joychou;cat /etc/passwd
     * http://localhost:8080/codeinject/host
     */
    @GetMapping("/codeinject/host")
    public String codeInjectHost(HttpServletRequest request) throws IOException {

        String host = request.getHeader("host");
        logger.info("Host header received");
        if (host == null || !HOST_PATTERN.matcher(host).matches()) {
            return "Bad boy. I got u.";
        }
        // No process is spawned: fetch in-process over TLS only, after the SSRF check on the target.
        String url = "https://" + host + "/";
        if (!SSRFChecker.isSafeHttpUrl(url)) {
            return "Bad boy. I got u.";
        }
        return HtmlUtils.htmlEscape(HttpUtils.URLConnectionHttpsOnly(url));
    }

    @GetMapping("/codeinject/sec")
    public String codeInjectSec(String filepath) throws IOException {
        return listDirectory(filepath);
    }
}
