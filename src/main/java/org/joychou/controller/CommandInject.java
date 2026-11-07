package org.joychou.controller;

import org.joychou.util.WebUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

@RestController
public class CommandInject {

    protected final Logger logger = LoggerFactory.getLogger(this.getClass());

    /**
     * Fixed server-side allowlists: the request only selects a key, the value placed in the
     * argv is a hard-coded constant, never request data.
     */
    private static final Map<String, String> LIST_PATHS;
    private static final Map<String, String> HOSTS;

    static {
        Map<String, String> paths = new HashMap<>();
        paths.put("/tmp", "/tmp");
        paths.put("/var/log", "/var/log");
        LIST_PATHS = Collections.unmodifiableMap(paths);

        Map<String, String> hosts = new HashMap<>();
        hosts.put("localhost", "localhost");
        hosts.put("localhost:8080", "localhost:8080");
        hosts.put("127.0.0.1", "127.0.0.1");
        hosts.put("127.0.0.1:8080", "127.0.0.1:8080");
        HOSTS = Collections.unmodifiableMap(hosts);
    }

    private static String[] lsCommand(String key) {
        String fixedPath = key == null ? null : LIST_PATHS.get(key);
        if (fixedPath == null) {
            return null;
        }
        return new String[]{"ls", "-la", "--", fixedPath};
    }

    /**
     * http://localhost:8080/codeinject?filepath=/tmp
     *
     * @param filepath key of an allowlisted directory
     * @return result
     */
    @GetMapping("/codeinject")
    public String codeInject(String filepath) throws IOException {

        String[] cmdList = lsCommand(filepath);
        if (cmdList == null) {
            return "Bad boy. I got u.";
        }
        ProcessBuilder builder = new ProcessBuilder(cmdList);
        builder.redirectErrorStream(true);
        Process process = builder.start();
        return WebUtils.htmlEscape(WebUtils.convertStreamToString(process.getInputStream()));
    }

    /**
     * Host Injection
     * Host: hacked by joychou;cat /etc/passwd
     * http://localhost:8080/codeinject/host
     */
    @GetMapping("/codeinject/host")
    public String codeInjectHost(HttpServletRequest request) throws IOException {

        String host = request.getHeader("host");
        logger.info("codeinject/host request received");
        // Only allowlisted hosts are accepted; the argv uses the hard-coded allowlist value.
        String fixedHost = host == null ? null : HOSTS.get(host);
        if (fixedHost == null) {
            return "Bad boy. I got u.";
        }
        String[] cmdList = new String[]{"curl", "--", fixedHost};
        ProcessBuilder builder = new ProcessBuilder(cmdList);
        builder.redirectErrorStream(true);
        Process process = builder.start();
        return WebUtils.htmlEscape(WebUtils.convertStreamToString(process.getInputStream()));
    }

    @GetMapping("/codeinject/sec")
    public String codeInjectSec(String filepath) throws IOException {
        String[] cmdList = lsCommand(filepath);
        if (cmdList == null) {
            return "Bad boy. I got u.";
        }
        ProcessBuilder builder = new ProcessBuilder(cmdList);
        builder.redirectErrorStream(true);
        Process process = builder.start();
        return WebUtils.htmlEscape(WebUtils.convertStreamToString(process.getInputStream()));
    }
}
