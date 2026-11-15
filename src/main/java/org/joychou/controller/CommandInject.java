package org.joychou.controller;

import org.springframework.web.util.HtmlUtils;
import org.joychou.security.SecurityUtil;
import org.joychou.util.WebUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

@RestController
public class CommandInject {

    private static final Map<String, String> FIXED_HOSTS = new HashMap<String, String>();
    static {
        FIXED_HOSTS.put("localhost", "localhost");
        FIXED_HOSTS.put("localhost:8080", "localhost:8080");
        FIXED_HOSTS.put("127.0.0.1", "127.0.0.1");
        FIXED_HOSTS.put("127.0.0.1:8080", "127.0.0.1:8080");
    }

    protected final Logger logger = LoggerFactory.getLogger(this.getClass());

    /**
     * http://localhost:8080/codeinject?filepath=/tmp;cat /etc/passwd
     *
     * @param filepath filepath
     * @return result
     */
    @GetMapping("/codeinject")
    public String codeInject(String filepath) throws IOException {

        // The request value is only a lookup key; the argv element comes from a fixed server-side constant.
        String dir = SecurityUtil.fixedDir(filepath);
        if (dir == null) {
            return "Bad boy. I got u.";
        }
        String[] cmdList = new String[]{"ls", "-la", "--", dir};
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
        // The header value is only a lookup key; the argv element is a fixed server-side constant.
        String fixedHost = host == null ? null : FIXED_HOSTS.get(host.toLowerCase());
        if (fixedHost == null) {
            return "Bad boy. I got u.";
        }
        String[] cmdList = new String[]{"curl", "--", fixedHost};
        ProcessBuilder builder = new ProcessBuilder(cmdList);
        builder.redirectErrorStream(true);
        Process process = builder.start();
        return HtmlUtils.htmlEscape(WebUtils.convertStreamToString(process.getInputStream()));
    }

    @GetMapping("/codeinject/sec")
    public String codeInjectSec(String filepath) throws IOException {
        String dir = SecurityUtil.fixedDir(filepath);
        if (null == dir) {
            return "Bad boy. I got u.";
        }
        String[] cmdList = new String[]{"ls", "-la", "--", dir};
        ProcessBuilder builder = new ProcessBuilder(cmdList);
        builder.redirectErrorStream(true);
        Process process = builder.start();
        return HtmlUtils.htmlEscape(WebUtils.convertStreamToString(process.getInputStream()));
    }
}
