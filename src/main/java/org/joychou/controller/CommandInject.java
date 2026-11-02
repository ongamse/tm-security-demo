package org.joychou.controller;

import org.joychou.security.SafeCommand;
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
        // Fixed "ls -la --" argv; the strictly validated path is the only variable element.
        String output = SafeCommand.listDirectory(filepath);
        if (null == output) {
            return "Bad boy. I got u.";
        }
        return HtmlUtils.htmlEscape(output);
    }

    /**
     * Host Injection
     * Host: hacked by joychou;cat /etc/passwd
     * http://localhost:8080/codeinject/host
     */
    @GetMapping("/codeinject/host")
    public String codeInjectHost(HttpServletRequest request) throws IOException {

        String host = request.getHeader("host");
        String output = SafeCommand.curlHost(host);
        if (null == output) {
            return "Bad boy. I got u.";
        }
        return HtmlUtils.htmlEscape(output);
    }

    @GetMapping("/codeinject/sec")
    public String codeInjectSec(String filepath) throws IOException {
        String output = SafeCommand.listDirectory(filepath);
        if (null == output) {
            return "Bad boy. I got u.";
        }
        return HtmlUtils.htmlEscape(output);
    }
}
