package org.joychou.controller;

import org.joychou.security.SecurityUtil;
import org.joychou.util.WebUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.regex.Pattern;

@RestController
public class CommandInject {

    protected final Logger logger = LoggerFactory.getLogger(this.getClass());

    // hostname (optionally with port); no leading '-' so it cannot be parsed as an option
    private static final Pattern HOST_PATTERN = Pattern.compile("^[a-zA-Z0-9][a-zA-Z0-9.-]*(:[0-9]{1,5})?$");

    /**
     * http://localhost:8080/codeinject?filepath=/tmp;cat /etc/passwd
     *
     * @param filepath filepath
     * @return result
     */
    @GetMapping("/codeinject")
    public String codeInject(String filepath) throws IOException {

        // the directory is looked up in a fixed allowlist: argv only ever holds code literals
        String safePath = SecurityUtil.allowedDirectory(filepath);
        if (null == safePath) {
            return "Bad boy. I got u.";
        }
        // no shell: argv only, "--" ends option parsing
        String[] cmdList = new String[]{"ls", "-la", "--", safePath};
        ProcessBuilder builder = new ProcessBuilder(cmdList);
        builder.redirectErrorStream(true);
        Process process = builder.start();
        return WebUtils.escapeHtml(WebUtils.convertStreamToString(process.getInputStream()));
    }

    /**
     * Host Injection
     * Host: hacked by joychou;cat /etc/passwd
     * http://localhost:8080/codeinject/host
     */
    @GetMapping("/codeinject/host")
    public String codeInjectHost(HttpServletRequest request) throws IOException {

        String host = request.getHeader("host");
        logger.info("Host header received, length: {}", null == host ? 0 : host.length());
        if (null == host || !HOST_PATTERN.matcher(host).matches()) {
            return "Bad boy. I got u.";
        }
        // canonical url rebuilt from the resolved public IP and parsed port, not the header string
        String url = SecurityUtil.canonicalHostUrl(host);
        if (null == url) {
            return "Bad boy. I got u.";
        }
        // no shell: argv only
        String[] cmdList = new String[]{"curl", "--proto", "=https", "--tlsv1.2", "--", url};
        ProcessBuilder builder = new ProcessBuilder(cmdList);
        builder.redirectErrorStream(true);
        Process process = builder.start();
        return WebUtils.escapeHtml(WebUtils.convertStreamToString(process.getInputStream()));
    }

    @GetMapping("/codeinject/sec")
    public String codeInjectSec(String filepath) throws IOException {
        // the directory is looked up in a fixed allowlist: argv only ever holds code literals
        String filterFilePath = SecurityUtil.allowedDirectory(filepath);
        if (null == filterFilePath) {
            return "Bad boy. I got u.";
        }
        // no shell: argv only, "--" ends option parsing
        String[] cmdList = new String[]{"ls", "-la", "--", filterFilePath};
        ProcessBuilder builder = new ProcessBuilder(cmdList);
        builder.redirectErrorStream(true);
        Process process = builder.start();
        return WebUtils.escapeHtml(WebUtils.convertStreamToString(process.getInputStream()));
    }
}
