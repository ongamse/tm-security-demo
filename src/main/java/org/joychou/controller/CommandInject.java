package org.joychou.controller;

import org.joychou.security.SecurityUtil;
import org.joychou.util.WebUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import org.springframework.web.util.HtmlUtils;

@RestController
public class CommandInject {

    protected final Logger logger = LoggerFactory.getLogger(this.getClass());
    private static final java.util.Set<String> ALLOWED_HOSTS = new java.util.HashSet<>(
            java.util.Arrays.asList("localhost", "localhost:8080", "127.0.0.1", "127.0.0.1:8080"));
    private static final java.util.regex.Pattern SAFE_PATH_PATTERN =
            java.util.regex.Pattern.compile("^[a-zA-Z0-9/._-]+$");

    /**
     * http://localhost:8080/codeinject?filepath=/tmp
     *
     * @param filepath filepath
     * @return result
     */
    @GetMapping("/codeinject")
    public String codeInject(String filepath) throws IOException {
        // Strict filepath validation: only safe characters, no traversal
        if (filepath == null || !SAFE_PATH_PATTERN.matcher(filepath).matches() || filepath.contains("..")) {
            return "Invalid filepath.";
        }
        String[] cmdList = new String[]{"ls", "-la", filepath};
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
        logger.info(host);
        // Validate host against strict allowlist of known hosts
        if (host == null || !ALLOWED_HOSTS.contains(host.toLowerCase())) {
            return "Invalid host header.";
        }
        String[] cmdList = new String[]{"curl", host};
        ProcessBuilder builder = new ProcessBuilder(cmdList);
        builder.redirectErrorStream(true);
        Process process = builder.start();
        return HtmlUtils.htmlEscape(WebUtils.convertStreamToString(process.getInputStream()));
    }

    @GetMapping("/codeinject/sec")
    public String codeInjectSec(String filepath) throws IOException {
        // Double-validate: SecurityUtil.cmdFilter + explicit traversal and pattern check
        if (filepath == null || !SAFE_PATH_PATTERN.matcher(filepath).matches() || filepath.contains("..")) {
            return "Invalid filepath.";
        }
        String filterFilePath = SecurityUtil.cmdFilter(filepath);
        if (null == filterFilePath) {
            return "Bad boy. I got u.";
        }
        String[] cmdList = new String[]{"ls", "-la", filterFilePath};
        ProcessBuilder builder = new ProcessBuilder(cmdList);
        builder.redirectErrorStream(true);
        Process process = builder.start();
        return HtmlUtils.htmlEscape(WebUtils.convertStreamToString(process.getInputStream()));
    }
}
