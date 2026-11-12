package org.joychou.controller;

import org.joychou.security.SecurityUtil;
import org.springframework.web.util.HtmlUtils;
import org.joychou.util.WebUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.List;

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

        // Fixed "ls -la --" from the server-side table + one validated path token; no shell.
        List<String> cmdList = SecurityUtil.buildListCommand(filepath);
        if (null == cmdList) {
            return "Bad boy. I got u.";
        }
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
        // Fixed curl options + one validated host token after "--"; no shell.
        List<String> cmdList = SecurityUtil.buildCurlHostCommand(host);
        if (cmdList == null) {
            return "Bad boy. I got u.";
        }
        ProcessBuilder builder = new ProcessBuilder(cmdList);
        builder.redirectErrorStream(true);
        Process process = builder.start();
        return HtmlUtils.htmlEscape(WebUtils.convertStreamToString(process.getInputStream()));
    }

    @GetMapping("/codeinject/sec")
    public String codeInjectSec(String filepath) throws IOException {
        List<String> cmdList = SecurityUtil.buildListCommand(filepath);
        if (null == cmdList) {
            return "Bad boy. I got u.";
        }
        ProcessBuilder builder = new ProcessBuilder(cmdList);
        builder.redirectErrorStream(true);
        Process process = builder.start();
        return HtmlUtils.htmlEscape(WebUtils.convertStreamToString(process.getInputStream()));
    }
}
