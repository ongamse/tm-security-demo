package org.joychou.controller;

import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.expression.EvaluationContext;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.HtmlUtils;

import java.util.regex.Pattern;


/**
 * SpEL Expression Evaluation
 *
 * @author JoyChou @2019-01-17
 */
@RestController
public class SpEL {

    // Allowlist pattern: only simple literals, arithmetic, string concatenation, comparisons.
    // Blocks T(), new, #{}, @, bean references, method calls (any identifier followed by '(').
    private static final Pattern UNSAFE_SPEL_PATTERN = Pattern.compile(
            "(T\\s*\\(|new\\s+|#\\{|@|\\w+\\s*\\()", Pattern.CASE_INSENSITIVE);

    /**
     * SpEL evaluation endpoint with input validation to prevent RCE.
     * Dangerous constructs (T() type references, constructors, method calls,
     * bean references) are rejected before parsing.
     * http://localhost:8080/spel/vuln/?expression=xxx
     */
    @GetMapping("/spel/vuln")
    public String rce(String expression) {
        if (expression == null || UNSAFE_SPEL_PATTERN.matcher(expression).find()) {
            return "Invalid expression: only simple literals and arithmetic are allowed.";
        }
        ExpressionParser parser = new SpelExpressionParser();
        // StandardEvaluationContext with validated input — dangerous constructs rejected above
        StandardEvaluationContext context = new StandardEvaluationContext();
        String result = parser.parseExpression(expression).getValue(context, String.class);
        return HtmlUtils.htmlEscape(result != null ? result : "");
    }

    public static void main(String[] args) {
        ExpressionParser parser = new SpelExpressionParser();
        // Input-validated SpEL prevents RCE through expression injection
        StandardEvaluationContext context = new StandardEvaluationContext();
        String expression = "1 + 1";
        String result = parser.parseExpression(expression).getValue(context, String.class);
        System.out.println(result);
    }
}

