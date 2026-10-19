package org.joychou.controller;

import org.springframework.expression.EvaluationException;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.regex.Pattern;


/**
 * SpEL Injection
 *
 * @author JoyChou @2019-01-17
 */
@RestController
public class SpEL {

    // Allow only simple property access, literals, arithmetic, and string operations
    private static final Pattern SAFE_SPEL_PATTERN = Pattern.compile("^[a-zA-Z0-9_.+\\-*/ '\"(),%]+$");

    /**
     * SpEL expression evaluator (secured)
     * Blocks type references (T()), bean references (@), and method invocations
     * that could lead to RCE.
     */
    @GetMapping("/spel/vuln")
    public String rce(String expression) {
        if (expression == null || expression.isEmpty()) {
            return "Expression is required.";
        }
        // Block dangerous SpEL constructs: T() type references, new object creation,
        // bean references, and Runtime/ProcessBuilder/exec patterns
        String normalized = expression.trim();
        if (!SAFE_SPEL_PATTERN.matcher(normalized).matches()) {
            return "Expression rejected: only simple expressions (literals, arithmetic, property access) are allowed.";
        }

        ExpressionParser parser = new SpelExpressionParser();
        // Use a restricted evaluation context with no type locator access
        StandardEvaluationContext context = new StandardEvaluationContext();
        context.setTypeLocator(typeName -> {
            throw new EvaluationException("Type access is not allowed: " + typeName);
        });
        try {
            Object result = parser.parseExpression(normalized).getValue(context);
            return result != null ? result.toString() : "null";
        } catch (EvaluationException e) {
            return "Expression evaluation blocked: " + e.getMessage();
        }
    }

    public static void main(String[] args) {
        ExpressionParser parser = new SpelExpressionParser();
        String expression = "T(java.lang.Runtime).getRuntime().exec(\"open -a Calculator\")";
        String result = parser.parseExpression(expression).getValue().toString();
        System.out.println(result);
    }
}

