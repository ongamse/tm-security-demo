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
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.regex.Pattern;

@RestController
public class CommandInject {

    protected final Logger logger = LoggerFactory.getLogger(this.getClass());

    private static final Pattern SAFE_PATH_PATTERN = Pattern.compile("^[a-zA-Z0-9_/\\-.]+$");

    private static final Set<String> ALLOWED_HOSTS = new HashSet<>(Arrays.asList(
            "localhost", "127.0.0.1"
    ));

    /**
     * http://localhost:8080/codeinject?filepath=/tmp
     *
     * @param filepath filepath
     * @return result
     */
    @GetMapping("/codeinject")
    public String codeInject(String filepath) throws IOException {
        if (filepath == null || !SAFE_PATH_PATTERN.matcher(filepath).matches()) {
            return "Invalid filepath. Only alphanumeric characters, slashes, dashes, dots, and underscores are allowed.";
        }
        // Canonicalize to prevent path traversal
        Path canonical = Paths.get(filepath).normalize();
        if (canonical.toString().contains("..")) {
            return "Invalid filepath.";
        }
        // Use ProcessBuilder with explicit argument array; no shell interpretation
        ProcessBuilder builder = new ProcessBuilder("ls", "-la", canonical.toString());
        builder.redirectErrorStream(true);
        Process process = builder.start();
        return HtmlUtils.htmlEscape(WebUtils.convertStreamToString(process.getInputStream()));
    }

    /**
     * Host header info
     * http://localhost:8080/codeinject/host
     */
    @GetMapping("/codeinject/host")
    public String codeInjectHost(HttpServletRequest request) throws IOException {
        String host = request.getHeader("host");
        if (host == null) {
            return "Missing host header.";
        }
        // Strip port if present for validation
        String hostOnly = host.contains(":") ? host.substring(0, host.indexOf(':')) : host;
        if (!ALLOWED_HOSTS.contains(hostOnly)) {
            return "Host not allowed. Allowed hosts: " + ALLOWED_HOSTS;
        }
        logger.info(host);
        // Use ProcessBuilder with explicit argument array; no shell interpretation
        ProcessBuilder builder = new ProcessBuilder("curl", host);
        builder.redirectErrorStream(true);
        Process process = builder.start();
        return HtmlUtils.htmlEscape(WebUtils.convertStreamToString(process.getInputStream()));
    }

    @GetMapping("/codeinject/sec")
    public String codeInjectSec(String filepath) throws IOException {
        String filterFilePath = SecurityUtil.cmdFilter(filepath);
        if (null == filterFilePath) {
            return "Bad boy. I got u.";
        }
        // Use ProcessBuilder with explicit argument array; no shell interpretation
        ProcessBuilder builder = new ProcessBuilder("ls", "-la", filterFilePath);
        builder.redirectErrorStream(true);
        Process process = builder.start();
        return HtmlUtils.htmlEscape(WebUtils.convertStreamToString(process.getInputStream()));
    }
}
