package org.joychou.controller;

import org.joychou.security.SecurityUtil;
import org.joychou.util.WebUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
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

        // No shell. The argv is built from constants and the canonical path of a real directory entry
        // below the temp directory; "--" stops option parsing.
        String[] cmdList = SecurityUtil.lsArgv(filepath);
        if (null == cmdList) {
            return "Bad boy. I got u.";
        }
        ProcessBuilder builder = new ProcessBuilder(cmdList);
        builder.redirectErrorStream(true);
        Process process = builder.start();
        return WebUtils.htmlEncode(WebUtils.convertStreamToString(process.getInputStream()));
    }

    /**
     * Host Injection
     * Host: hacked by joychou;cat /etc/passwd
     * http://localhost:8080/codeinject/host
     */
    @GetMapping("/codeinject/host")
    public String codeInjectHost(HttpServletRequest request) throws IOException {

        String host = request.getHeader("host");
        logger.info(WebUtils.sanitizeLog(host));
        // No shell. The argv is built from constants and the configured safe-domain value that the
        // Host header selected; "--" stops option parsing.
        String[] cmdList = SecurityUtil.curlArgv(host);
        if (cmdList == null) {
            return "Bad boy. I got u.";
        }
        ProcessBuilder builder = new ProcessBuilder(cmdList);
        builder.redirectErrorStream(true);
        Process process = builder.start();
        return WebUtils.htmlEncode(WebUtils.convertStreamToString(process.getInputStream()));
    }

    @GetMapping("/codeinject/sec")
    public String codeInjectSec(String filepath) throws IOException {
        String[] cmdList = SecurityUtil.lsArgv(filepath);
        if (null == cmdList) {
            return "Bad boy. I got u.";
        }
        ProcessBuilder builder = new ProcessBuilder(cmdList);
        builder.redirectErrorStream(true);
        Process process = builder.start();
        return WebUtils.convertStreamToString(process.getInputStream());
    }
}
