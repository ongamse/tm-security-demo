package org.joychou.controller;

import java.util.regex.Pattern;

import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.HtmlUtils;


/**
 * SpEL Injection
 *
 * @author JoyChou @2019-01-17
 */
@RestController
public class SpEL {

    // Allowlist: only simple property-access expressions (letters, digits, dots, underscores)
    private static final Pattern SAFE_SPEL_PATTERN = Pattern.compile("^[a-zA-Z0-9_.]+$");

    // Blocklist of dangerous SpEL patterns that enable RCE / reflection
    private static final Pattern DANGEROUS_SPEL_PATTERN = Pattern.compile(
            "T\\s*\\(|Runtime|exec|Class|forName|getRuntime|\\.class|new\\s|#|\\{|\\[|getClass",
            Pattern.CASE_INSENSITIVE);

    private static boolean isSafeExpression(String expression) {
        if (expression == null || expression.isEmpty()) {
            return false;
        }
        if (DANGEROUS_SPEL_PATTERN.matcher(expression).find()) {
            return false;
        }
        return SAFE_SPEL_PATTERN.matcher(expression).matches();
    }

    /**
     * SpEL expression evaluation with input validation to prevent injection.
     * Only simple property-access expressions (alphanumeric, dots, underscores) are allowed.
     * http://localhost:8080/spel/vuln/?expression=xxx
     */
    @GetMapping("/spel/vuln")
    public String rce(String expression) {
        if (!isSafeExpression(expression)) {
            return "Expression rejected: only simple property access expressions are allowed.";
        }
        ExpressionParser parser = new SpelExpressionParser();
        String result = parser.parseExpression(expression).getValue(String.class);
        return HtmlUtils.htmlEscape(String.valueOf(result));
    }

    public static void main(String[] args) {
        // Removed: Runtime.exec() invocation via SpEL expression
        System.out.println("SpEL demo class loaded.");
    }
}

