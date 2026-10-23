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
     * http://localhost:8080/codeinject?filepath=/tmp
     *
     * @param filepath filepath
     * @return result
     */
    @GetMapping("/codeinject")
    public String codeInject(String filepath) throws IOException {
        // Validate filepath to prevent command injection
        String filteredPath = SecurityUtil.cmdFilter(filepath);
        if (null == filteredPath) {
            return "Invalid filepath: only alphanumeric characters, dots, hyphens, underscores, and slashes are allowed.";
        }

        // Use explicit argument array without shell to prevent command injection
        String[] cmdList = new String[]{"ls", "-la", filteredPath};
        ProcessBuilder builder = new ProcessBuilder(cmdList);
        builder.redirectErrorStream(true);
        Process process = builder.start();
        return WebUtils.convertStreamToString(process.getInputStream());
    }

    /**
     * Host header info
     * http://localhost:8080/codeinject/host
     */
    @GetMapping("/codeinject/host")
    public String codeInjectHost(HttpServletRequest request) throws IOException {

        String host = request.getHeader("host");
        // Validate host header to prevent command injection
        String filteredHost = SecurityUtil.cmdFilter(host);
        if (null == filteredHost) {
            return "Invalid host header: only alphanumeric characters, dots, hyphens, underscores, and slashes are allowed.";
        }
        logger.info(filteredHost);
        // Use explicit argument array without shell to prevent command injection
        String[] cmdList = new String[]{"curl", filteredHost};
        ProcessBuilder builder = new ProcessBuilder(cmdList);
        builder.redirectErrorStream(true);
        Process process = builder.start();
        return WebUtils.convertStreamToString(process.getInputStream());
    }

    @GetMapping("/codeinject/sec")
    public String codeInjectSec(String filepath) throws IOException {
        String filterFilePath = SecurityUtil.cmdFilter(filepath);
        if (null == filterFilePath) {
            return "Bad boy. I got u.";
        }
        // Use explicit argument array without shell to prevent command injection
        String[] cmdList = new String[]{"ls", "-la", filterFilePath};
        ProcessBuilder builder = new ProcessBuilder(cmdList);
        builder.redirectErrorStream(true);
        Process process = builder.start();
        return WebUtils.convertStreamToString(process.getInputStream());
    }
}
