package org.joychou.controller;

import org.springframework.expression.EvaluationException;
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

    /**
     * Creates a restricted evaluation context that prevents RCE by:
     * - Blocking all type references (T() expressions) via a custom TypeLocator
     * - Blocking all constructor invocations (new expressions) via empty resolvers
     * Compatible with Spring 4.x (SimpleEvaluationContext requires Spring 5+).
     */
    private static StandardEvaluationContext createRestrictedContext() {
        StandardEvaluationContext context = new StandardEvaluationContext();
        // Block T() type references - prevents T(java.lang.Runtime).getRuntime().exec(...)
        context.setTypeLocator(typeName -> {
            throw new EvaluationException("Type references are not allowed in SpEL expressions: " + typeName);
        });
        // Block new expressions - prevents new java.lang.ProcessBuilder(...)
        context.setConstructorResolvers(Collections.emptyList());
        return context;
    }

    /**
     * SpEL evaluation endpoint.
     * Uses a restricted StandardEvaluationContext to prevent type references and RCE.
     */
    @GetMapping("/spel/vuln")
    public String rce(String expression) {
        ExpressionParser parser = new SpelExpressionParser();
        StandardEvaluationContext context = createRestrictedContext();
        String result = parser.parseExpression(expression).getValue(context, String.class);
        return HtmlUtils.htmlEscape(result != null ? result : "");
    }

    public static void main(String[] args) {
        ExpressionParser parser = new SpelExpressionParser();
        StandardEvaluationContext context = createRestrictedContext();
        String expression = "'Hello World'";
        String result = parser.parseExpression(expression).getValue(context, String.class);
        System.out.println(result);
    }
}

