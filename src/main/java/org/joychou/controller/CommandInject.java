package org.joychou.controller;

import org.springframework.web.util.HtmlUtils;
import org.joychou.config.WebConfig;
import org.joychou.security.SecurityUtil;
import org.joychou.security.ssrf.SSRFChecker;
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

        String safePath = SecurityUtil.allowedListPath(filepath);
        if (null == safePath) {
            return "Bad boy. I got u.";
        }
        String[] cmdList = new String[]{"ls", "-la", "--", safePath};
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
        // Host header is attacker-controlled: it is only used to select an entry of the configured
        // SSRF safe-domain list; the URL passed to curl is built from the configured entry itself.
        String safeHost = null;
        if (host != null) {
            for (String domain : WebConfig.getSsrfSafeDomains()) {
                if (domain.equals(host)) {
                    safeHost = domain;
                    break;
                }
            }
        }
        if (safeHost == null) {
            return "Bad boy. I got u.";
        }
        // central SSRF control: scheme/host/internal-address check and rebuilt url
        String url = SSRFChecker.safeUrlOrNull("http://" + safeHost);
        if (url == null) {
            return "Bad boy. I got u.";
        }
        String[] cmdList = new String[]{"curl", "--", url};
        ProcessBuilder builder = new ProcessBuilder(cmdList);
        builder.redirectErrorStream(true);
        Process process = builder.start();
        return HtmlUtils.htmlEscape(WebUtils.convertStreamToString(process.getInputStream()));
    }

    @GetMapping("/codeinject/sec")
    public String codeInjectSec(String filepath) throws IOException {
        String filterFilePath = SecurityUtil.allowedListPath(filepath);
        if (null == filterFilePath) {
            return "Bad boy. I got u.";
        }
        String[] cmdList = new String[]{"ls", "-la", "--", filterFilePath};
        ProcessBuilder builder = new ProcessBuilder(cmdList);
        builder.redirectErrorStream(true);
        Process process = builder.start();
        return HtmlUtils.htmlEscape(WebUtils.convertStreamToString(process.getInputStream()));
    }
}
