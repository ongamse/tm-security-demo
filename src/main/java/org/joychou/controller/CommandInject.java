package org.joychou.controller;

import org.joychou.security.SecurityUtil;
import org.joychou.util.WebUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.HtmlUtils;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

@RestController
public class CommandInject {

    protected final Logger logger = LoggerFactory.getLogger(this.getClass());

    // Fixed directory that the listing endpoints may inspect.
    private static final Path BASE_DIR = Paths.get(System.getProperty("java.io.tmpdir")).toAbsolutePath().normalize();

    // Known hosts: the request value only selects one of these constants.
    private static final Map<String, String> ALLOWED_HOSTS;

    static {
        Map<String, String> hosts = new HashMap<>();
        hosts.put("localhost", "localhost");
        hosts.put("localhost:8080", "localhost:8080");
        hosts.put("127.0.0.1", "127.0.0.1");
        hosts.put("127.0.0.1:8080", "127.0.0.1:8080");
        ALLOWED_HOSTS = Collections.unmodifiableMap(hosts);
    }

    /**
     * Identifier lookup: find the entry of BASE_DIR whose name equals the requested name and return
     * the server-side path of that entry. The request string itself is never used as the path.
     *
     * @return server-resolved absolute path, or null if there is no such entry
     */
    private static String resolveUnderBase(String name) throws IOException {
        if (name == null || name.isEmpty()) {
            return BASE_DIR.toString();
        }
        try (DirectoryStream<Path> entries = Files.newDirectoryStream(BASE_DIR)) {
            for (Path entry : entries) {
                if (entry.getFileName().toString().equals(name)) {
                    return entry.toAbsolutePath().normalize().toString();
                }
            }
        }
        return null;
    }

    /**
     * http://localhost:8080/codeinject?filepath=/tmp;cat /etc/passwd
     *
     * @param filepath filepath
     * @return result
     */
    @GetMapping("/codeinject")
    public String codeInject(String filepath) throws IOException {

        String filterFilePath = resolveUnderBase(filepath);
        if (null == filterFilePath) {
            return "Bad boy. I got u.";
        }
        // No shell: the path is passed as a single argv element after "--".
        String[] cmdList = new String[]{"ls", "-la", "--", filterFilePath};
        ProcessBuilder builder = new ProcessBuilder(cmdList);
        builder.redirectErrorStream(true);
        Process process = builder.start();
        return HtmlUtils.htmlEscape(WebUtils.convertStreamToString(process.getInputStream()));
    }

    /**
     * Host Injection
     * Host: hacked by joychou;cat /etc/passwd
     * http://localhost:8080/codeinject/host
     */
    @GetMapping("/codeinject/host")
    public String codeInjectHost(HttpServletRequest request) throws IOException {

        String host = request.getHeader("host");
        logger.info("Host header: {}", SecurityUtil.logSafe(host));
        String knownHost = host == null ? null : ALLOWED_HOSTS.get(host);
        if (knownHost == null) {
            return "Bad boy. I got u.";
        }
        // No shell: a constant host from the allowlist map is passed as a single argv element after "--".
        String[] cmdList = new String[]{"curl", "--max-time", "5", "--", knownHost};
        ProcessBuilder builder = new ProcessBuilder(cmdList);
        builder.redirectErrorStream(true);
        Process process = builder.start();
        return HtmlUtils.htmlEscape(WebUtils.convertStreamToString(process.getInputStream()));
    }

    @GetMapping("/codeinject/sec")
    public String codeInjectSec(String filepath) throws IOException {
        String filterFilePath = resolveUnderBase(filepath);
        if (null == filterFilePath) {
            return "Bad boy. I got u.";
        }
        String[] cmdList = new String[]{"ls", "-la", "--", filterFilePath};
        ProcessBuilder builder = new ProcessBuilder(cmdList);
        builder.redirectErrorStream(true);
        Process process = builder.start();
        return HtmlUtils.htmlEscape(WebUtils.convertStreamToString(process.getInputStream()));
    }
}
