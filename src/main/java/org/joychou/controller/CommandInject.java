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

        // Reject (never sanitise) anything that is not a plain path: no flags, no "..", no metacharacters.
        String safePath = SecurityUtil.safePathArg(filepath);
        if (safePath == null) {
            return "Bad boy. I got u.";
        }
        String[] cmdList = new String[]{"ls", "-la", "--", safePath};
        if (!SecurityUtil.isAllowedArgv(cmdList)) {
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
        // Reject anything that is not a plain host[:port]; the value can never become a flag,
        // a path, a URL scheme or a shell fragment.
        String safeHost = SecurityUtil.safeHostArg(host);
        if (safeHost == null) {
            return "Bad boy. I got u.";
        }
        String[] cmdList = new String[]{"curl", "--proto", "=http,https", "--max-time", "10",
                "--", "http://" + safeHost};
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
        String safePath = SecurityUtil.safePathArg(filterFilePath);
        if (safePath == null) {
            return "Bad boy. I got u.";
        }
        String[] cmdList = new String[]{"ls", "-la", "--", safePath};
        if (!SecurityUtil.isAllowedArgv(cmdList)) {
            return "Bad boy. I got u.";
        }
        ProcessBuilder builder = new ProcessBuilder(cmdList);
        builder.redirectErrorStream(true);
        Process process = builder.start();
        return HtmlUtils.htmlEscape(WebUtils.convertStreamToString(process.getInputStream()));
    }
}
