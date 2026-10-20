package org.joychou.controller;

import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.SpelEvaluationException;
import org.springframework.expression.spel.SpelMessage;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.web.bind.annotation.GetMapping;
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

    // Allowlist: only safe SpEL expressions — literals, simple arithmetic, string concatenation,
    // comparisons, boolean logic. No T(), new, #{}, method calls, or property traversal.
    private static final Pattern SAFE_SPEL_PATTERN = Pattern.compile(
            "^[a-zA-Z0-9\\s+\\-*/%(),'\".<>=!&|?:]+$"
    );

    // Block patterns that indicate code execution attempts
    private static final Pattern DANGEROUS_SPEL_PATTERN = Pattern.compile(
            "(?i)(T\\s*\\(|new\\s+|#\\{|\\bgetClass\\b|\\bforName\\b|\\bgetRuntime\\b"
            + "|\\bexec\\b|\\bgetMethod\\b|\\binvoke\\b|\\bclass\\b|\\bClassLoader\\b"
            + "|\\bRuntime\\b|\\bProcessBuilder\\b|\\bThread\\b|\\bSystem\\b)"
    );

    /**
     * SpEL evaluation with expression allowlist validation (Spring 4.x compatible).
     * http://localhost:8080/spel/vuln/?expression=1+1
     * Only simple literal/arithmetic expressions are accepted.
     */
    @GetMapping("/spel/vuln")
    public String rce(String expression) {
        if (expression == null || expression.isEmpty()) {
            return "Expression must not be empty";
        }

        // Validate expression against allowlist pattern and block dangerous constructs
        if (!SAFE_SPEL_PATTERN.matcher(expression).matches()
                || DANGEROUS_SPEL_PATTERN.matcher(expression).find()) {
            return "Expression rejected: only simple literals and arithmetic are allowed";
        }

        ExpressionParser parser = new SpelExpressionParser();
        // Defense-in-depth: restrict StandardEvaluationContext even though
        // expression validation already blocks dangerous patterns (Spring 4.x compatible)
        StandardEvaluationContext context = new StandardEvaluationContext();
        context.setTypeLocator(typeName -> {
            throw new SpelEvaluationException(SpelMessage.TYPE_NOT_FOUND, typeName);
        });
        context.setConstructorResolvers(Collections.emptyList());
        context.setMethodResolvers(Collections.emptyList());
        return HtmlUtils.htmlEscape(parser.parseExpression(expression).getValue(context).toString());
    }

    public static void main(String[] args) {
        ExpressionParser parser = new SpelExpressionParser();
        String expression = "T(java.lang.Runtime).getRuntime().exec(\"open -a Calculator\")";
        String result = parser.parseExpression(expression).getValue().toString();
        System.out.println(result);
    }
}

