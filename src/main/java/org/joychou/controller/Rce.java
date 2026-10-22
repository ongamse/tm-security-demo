package org.joychou.controller;

import groovy.lang.GroovyShell;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;

import javax.script.Bindings;
import javax.script.ScriptContext;
import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;
import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.sql.DriverManager;
import java.util.Set;
import org.springframework.web.util.HtmlUtils;


/**
 * Java code execute
 *
 * @author JoyChou @ 2018-05-24
 */
@Slf4j
@RestController
@RequestMapping("/rce")
public class Rce {

    // Allowlist of safe commands that may be executed
    private static final Set<String> ALLOWED_COMMANDS = Set.of(
            "whoami", "hostname", "date", "uptime", "id", "uname"
    );

    @GetMapping("/runtime/exec")
    public String CommandExec(String cmd) {
        if (cmd == null || !ALLOWED_COMMANDS.contains(cmd.trim().toLowerCase())) {
            return "Command not allowed. Permitted commands: " + ALLOWED_COMMANDS;
        }

        Runtime run = Runtime.getRuntime();
        StringBuilder sb = new StringBuilder();

        try {
            // Use explicit argv array to avoid shell interpretation
            Process p = new ProcessBuilder(cmd.trim()).start();
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
        if (cmd == null || !ALLOWED_COMMANDS.contains(cmd.trim().toLowerCase())) {
            return "Command not allowed. Permitted commands: " + ALLOWED_COMMANDS;
        }

        StringBuilder sb = new StringBuilder();

        try {
            // Use explicit command without shell to prevent injection
            ProcessBuilder processBuilder = new ProcessBuilder(cmd.trim());
            Process p = processBuilder.start();
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
     * http://localhost:8080/rce/jscmd?jsurl=http://xx.yy/zz.js
     *
     * This endpoint no longer evaluates remote scripts. It only accepts
     * allowlisted script names that map to local safe operations.
     *
     * @param jsurl script name (must be in allowlist)
     */
    @GetMapping("/jscmd")
    public String jsEngine(String jsurl) throws Exception {
        // Allowlist of permitted script identifiers — no remote URL evaluation
        Set<String> allowedScripts = Set.of("hello", "version", "status");
        if (jsurl == null || !allowedScripts.contains(jsurl.trim().toLowerCase())) {
            return "Script not allowed. Permitted scripts: " + allowedScripts;
        }

        ScriptEngine engine = new ScriptEngineManager().getEngineByName("js");
        Bindings bindings = engine.getBindings(ScriptContext.ENGINE_SCOPE);
        // Remove dangerous Java type access from the engine scope
        bindings.remove("java");
        bindings.remove("javax");
        bindings.remove("Java");

        // Only evaluate safe, hardcoded scripts — never user input
        String safeScript;
        switch (jsurl.trim().toLowerCase()) {
            case "hello":
                safeScript = "'Hello World'";
                break;
            case "version":
                safeScript = "'1.0.0'";
                break;
            case "status":
                safeScript = "'OK'";
                break;
            default:
                return "Script not allowed.";
        }
        Object result = engine.eval(safeScript, bindings);
        return result != null ? result.toString() : "";
    }


    /**
     * Safely loads YAML content using SafeConstructor to prevent
     * deserialization-based code execution.
     *
     * @param content YAML content
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

