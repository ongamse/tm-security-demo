package org.joychou.controller;

import org.springframework.expression.EvaluationContext;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.expression.TypeLocator;
import org.springframework.expression.EvaluationException;
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
     * Pattern that matches only safe SpEL: literals, arithmetic, comparisons,
     * string concatenation. Rejects T(), new, #, java., exec, Runtime, etc.
     */
    private static final Pattern SAFE_SPEL_PATTERN = Pattern.compile(
            "^[a-zA-Z0-9\\s+\\-*/%().'\"<>=!&|,]+$"
    );

    /**
     * Patterns that must NOT appear in the expression (case-insensitive).
     */
    private static final Pattern DANGEROUS_SPEL_PATTERN = Pattern.compile(
            "(?i)(T\\s*\\(|new\\s+|#|java\\.|javax\\.|Runtime|exec|Process|Thread|Class|forName|getClass|invoke|getRuntime|getMethod|getDeclared|URLClassLoader|ScriptEngine|GroovyShell|import)"
    );

    /**
     * SpEL evaluation with restricted context
     * http://localhost:8080/spel/vuln/?expression=xxx.
     */
    @GetMapping("/spel/vuln")
    public String rce(String expression) {
        if (expression == null || expression.isEmpty()) {
            return "Expression is required";
        }
        // Block dangerous SpEL patterns that enable RCE
        if (!SAFE_SPEL_PATTERN.matcher(expression).matches()
                || DANGEROUS_SPEL_PATTERN.matcher(expression).find()) {
            return "Expression rejected: contains disallowed constructs";
        }
        ExpressionParser parser = new SpelExpressionParser();
        // Use a restricted StandardEvaluationContext that denies all type lookups
        StandardEvaluationContext context = new StandardEvaluationContext();
        context.setTypeLocator(new TypeLocator() {
            @Override
            public Class<?> findType(String typeName) throws EvaluationException {
                throw new EvaluationException("Type access is not allowed: " + typeName);
            }
        });
        Object result = parser.parseExpression(expression).getValue(context);
        return HtmlUtils.htmlEscape(result != null ? result.toString() : "");
    }

    public static void main(String[] args) {
        ExpressionParser parser = new SpelExpressionParser();
        String expression = "T(java.lang.Runtime).getRuntime().exec(\"open -a Calculator\")";
        String result = parser.parseExpression(expression).getValue().toString();
        System.out.println(result);
    }
}

