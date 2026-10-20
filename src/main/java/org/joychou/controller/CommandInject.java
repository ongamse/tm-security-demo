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
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.regex.Pattern;

@RestController
public class CommandInject {

    protected final Logger logger = LoggerFactory.getLogger(this.getClass());

    /** Only allow safe characters in filepath arguments (alphanumeric, slash, dot, hyphen, underscore). */
    private static final Pattern SAFE_PATH_PATTERN = Pattern.compile("^[a-zA-Z0-9/_\\-.]+$");

    /** Allowlist of permitted host values for the host-based command endpoint. */
    private static final Set<String> ALLOWED_HOSTS = Collections.unmodifiableSet(
            new HashSet<>(Arrays.asList("localhost", "127.0.0.1"))
    );

    /**
     * http://localhost:8080/codeinject?filepath=/tmp
     *
     * @param filepath filepath
     * @return result
     */
    @GetMapping("/codeinject")
    public String codeInject(String filepath) throws IOException {
        if (filepath == null || !SAFE_PATH_PATTERN.matcher(filepath).matches()) {
            return "Invalid filepath. Only alphanumeric characters, '/', '.', '-', '_' are allowed.";
        }
        // Use argument array without shell to prevent command injection
        ProcessBuilder builder = new ProcessBuilder("ls", "-la", filepath);
        builder.redirectErrorStream(true);
        Process process = builder.start();
        return HtmlUtils.htmlEscape(WebUtils.convertStreamToString(process.getInputStream()));
    }

    /**
     * Host header endpoint -- validates host against allowlist, uses argument array.
     * http://localhost:8080/codeinject/host
     */
    @GetMapping("/codeinject/host")
    public String codeInjectHost(HttpServletRequest request) throws IOException {
        String host = request.getHeader("host");
        logger.info(host);
        // Strip port if present for validation
        String hostOnly = (host != null && host.contains(":")) ? host.substring(0, host.indexOf(':')) : host;
        if (hostOnly == null || !ALLOWED_HOSTS.contains(hostOnly.toLowerCase())) {
            return "Host not allowed. Permitted hosts: " + ALLOWED_HOSTS;
        }
        // Use argument array without shell to prevent command injection
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
        // Use argument array without shell to prevent command injection
        ProcessBuilder builder = new ProcessBuilder("ls", "-la", filterFilePath);
        builder.redirectErrorStream(true);
        Process process = builder.start();
        return HtmlUtils.htmlEscape(WebUtils.convertStreamToString(process.getInputStream()));
    }
}
