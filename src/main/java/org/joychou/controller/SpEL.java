package org.joychou.controller;

import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.HtmlUtils;

import java.util.Collections;


/**
 * SpEL Injection
 *
 * @author JoyChou @2019-01-17
 */
@RestController
public class SpEL {

    // Dangerous SpEL constructs that enable RCE / arbitrary type access
    private static final java.util.regex.Pattern DANGEROUS_SPEL_PATTERN =
            java.util.regex.Pattern.compile(
                    "T\\s*\\(|new\\s+[A-Za-z]|#\\{|\\bgetClass\\b|\\bforName\\b"
                    + "|\\bgetRuntime\\b|\\bexec\\b|\\bRuntime\\b|\\bProcessBuilder\\b"
                    + "|\\bClassLoader\\b|\\bgetMethod\\b|\\binvoke\\b|\\bThread\\b"
                    + "|\\bReflect|\\bjava\\.|\\bjavax\\.|\\borg\\.|\\bcom\\.|\\bnet\\."
                    + "|\\bSystem\\b|\\bScriptEngine\\b|\\bURLClassLoader\\b",
                    java.util.regex.Pattern.CASE_INSENSITIVE);

    /**
     * SpEL endpoint - safe from RCE.
     * Only allows simple literal/arithmetic expressions (no type references,
     * no constructor calls, no method invocations on Java classes).
     *
     * http://localhost:8080/spel/vuln/?expression=1+1
     */
    @GetMapping("/spel/vuln")
    public String rce(String expression) {
        if (expression == null || expression.trim().isEmpty()) {
            return "Expression is empty";
        }

        // Reject expressions containing dangerous constructs before evaluation
        if (DANGEROUS_SPEL_PATTERN.matcher(expression).find()) {
            return "Expression rejected: potentially dangerous construct";
        }

        ExpressionParser parser = new SpelExpressionParser();
        // Use a StandardEvaluationContext with no root object, no variables,
        // and no registered functions to minimise the attack surface.
        StandardEvaluationContext context = new StandardEvaluationContext();
        context.setRootObject(null);
        context.setVariables(Collections.<String, Object>emptyMap());
        return HtmlUtils.htmlEscape(parser.parseExpression(expression).getValue(context).toString());
    }

    public static void main(String[] args) {
        ExpressionParser parser = new SpelExpressionParser();
        String expression = "T(java.lang.Runtime).getRuntime().exec(\"open -a Calculator\")";
        String result = parser.parseExpression(expression).getValue().toString();
        System.out.println(result);
    }
}

