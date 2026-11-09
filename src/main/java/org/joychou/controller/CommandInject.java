package org.joychou.controller;

import org.joychou.security.FixedCommands;
import org.joychou.util.WebUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.HtmlUtils;

import java.io.IOException;

@RestController
public class CommandInject {

    /**
     * http://localhost:8080/codeinject?filepath=list
     * The request value is only a key into a server-side catalogue of constant commands.
     *
     * @param filepath command key (e.g. "list")
     * @return result
     */
    @GetMapping("/codeinject")
    public String codeInject(String filepath) throws IOException {
        return runFixed(filepath);
    }

    /**
     * The former implementation ran an external curl against the Host header. Request headers
     * must never reach a process or an outbound fetch, so the endpoint now returns a constant message.
     * http://localhost:8080/codeinject/host
     */
    @GetMapping("/codeinject/host")
    public String codeInjectHost() {
        return "Host header processing is disabled.";
    }

    @GetMapping(value = "/codeinject/sec", produces = "text/plain;charset=UTF-8")
    public String codeInjectSec(String filepath) throws IOException {
        return runFixed(filepath);
    }

    private static String runFixed(String key) throws IOException {
        String[] cmdList = FixedCommands.lookup(key);
        if (null == cmdList) {
            return "Bad boy. I got u.";
        }
        ProcessBuilder builder = new ProcessBuilder(cmdList);
        builder.redirectErrorStream(true);
        Process process = builder.start();
        return HtmlUtils.htmlEscape(WebUtils.convertStreamToString(process.getInputStream()));
    }
}
