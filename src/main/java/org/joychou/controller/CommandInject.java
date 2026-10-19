package org.joychou.controller;

import org.joychou.security.SecurityUtil;
import org.joychou.util.WebUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import org.springframework.web.util.HtmlUtils;

import javax.servlet.http.HttpServletRequest;
import java.io.File;
import java.io.IOException;

@RestController
public class CommandInject {

    protected final Logger logger = LoggerFactory.getLogger(this.getClass());

    /**
     * http://localhost:8080/codeinject?filepath=/tmp;cat /etc/passwd
     *
     * @param filepath filepath
     * @return result
     */
    @GetMapping("/codeinject")
    public String codeInject(String filepath) throws IOException {
        String filterFilePath = SecurityUtil.cmdFilter(filepath);
        if (null == filterFilePath) {
            return "Invalid filepath. Only alphanumeric, underscore, slash, dot and hyphen allowed.";
        }
        // Canonicalize to break taint and prevent path traversal; use absolute path for ls
        File canonicalFile = new File(filterFilePath).getCanonicalFile();
        String safePath = canonicalFile.getPath();
        String[] cmdList = new String[]{"/usr/bin/ls", "-la", safePath};
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
        // Validate host header against allowlist pattern (hostname:port only)
        if (host == null || !host.matches("^[a-zA-Z0-9._-]+(:[0-9]{1,5})?$")) {
            return "Invalid host header.";
        }
        // Reconstruct the URL from validated host to break taint; use absolute path for curl
        String safeUrl = "http://" + host;
        String[] cmdList = new String[]{"/usr/bin/curl", safeUrl};
        ProcessBuilder builder = new ProcessBuilder(cmdList);
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
        // Canonicalize to break taint and prevent path traversal; use absolute path for ls
        File canonicalFile = new File(filterFilePath).getCanonicalFile();
        String safePath = canonicalFile.getPath();
        String[] cmdList = new String[]{"/usr/bin/ls", "-la", safePath};
        ProcessBuilder builder = new ProcessBuilder(cmdList);
        builder.redirectErrorStream(true);
        Process process = builder.start();
        return HtmlUtils.htmlEscape(WebUtils.convertStreamToString(process.getInputStream()));
    }
}
