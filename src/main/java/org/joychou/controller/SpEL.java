package org.joychou.controller;

import org.springframework.expression.EvaluationContext;
import org.springframework.expression.EvaluationException;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.HtmlUtils;

import java.util.Collections;
import java.util.regex.Pattern;


/**
 * SpEL Injection
 *
 * @author JoyChou @2019-01-17
 */
@RestController
public class SpEL {

    // Patterns that indicate dangerous SpEL constructs (type access, instantiation, bean refs, method calls)
    private static final Pattern DANGEROUS_SPEL_PATTERN = Pattern.compile(
            "T\\s*\\(|new\\s+|#|\\{|getClass|forName|getRuntime|exec|invoke|getMethod",
            Pattern.CASE_INSENSITIVE
    );

    /**
     * Creates a restricted EvaluationContext that disables type resolution,
     * constructor resolution, and method resolution to prevent RCE via SpEL.
     * Compatible with Spring Framework 4.x (Spring Boot 1.x).
     */
    private static EvaluationContext createRestrictedContext() {
        StandardEvaluationContext ctx = new StandardEvaluationContext();
        // Remove all type, constructor, and method resolvers to block T(), new, and method calls
        ctx.setTypeLocator(typeName -> {
            throw new EvaluationException("Type access is not allowed: " + typeName);
        });
        ctx.setConstructorResolvers(Collections.emptyList());
        ctx.setMethodResolvers(Collections.emptyList());
        return ctx;
    }

    /**
     * SpEL endpoint — restricted to safe expressions only.
     * http://localhost:8080/spel/vuln/?expression=xxx.
     * Dangerous constructs (T(), new, bean refs, reflection) are rejected.
     */
    @GetMapping("/spel/vuln")
    public String rce(String expression) {
        if (expression == null || expression.trim().isEmpty()) {
            return "";
        }
        // First-pass allowlist: reject expressions containing dangerous patterns
        if (DANGEROUS_SPEL_PATTERN.matcher(expression).find()) {
            return "Expression rejected: potentially unsafe construct";
        }
        ExpressionParser parser = new SpelExpressionParser();
        // Use a restricted EvaluationContext with no type/constructor/method resolvers
        EvaluationContext context = createRestrictedContext();
        String result = parser.parseExpression(expression).getValue(context, String.class);
        return HtmlUtils.htmlEscape(result != null ? result : "");
    }

    public static void main(String[] args) {
        ExpressionParser parser = new SpelExpressionParser();
        String expression = "T(java.lang.Runtime).getRuntime().exec(\"open -a Calculator\")";
        String result = parser.parseExpression(expression).getValue().toString();
        System.out.println(result);
    }
}

