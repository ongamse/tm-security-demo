package org.joychou.controller;

import java.util.Collections;
import java.util.List;

import org.springframework.core.convert.TypeDescriptor;
import org.springframework.expression.AccessException;
import org.springframework.expression.ConstructorExecutor;
import org.springframework.expression.ConstructorResolver;
import org.springframework.expression.EvaluationContext;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.MethodExecutor;
import org.springframework.expression.MethodResolver;
import org.springframework.expression.TypeLocator;
import org.springframework.expression.spel.SpelEvaluationException;
import org.springframework.expression.spel.SpelMessage;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;
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

    /**
     * Creates a restricted EvaluationContext that blocks type references,
     * method invocations, and constructor calls to prevent SpEL injection / RCE.
     * Compatible with Spring 4.x (no SimpleEvaluationContext).
     */
    private static EvaluationContext createRestrictedContext() {
        StandardEvaluationContext ctx = new StandardEvaluationContext();

        // Block all T() type references — prevents T(java.lang.Runtime) etc.
        ctx.setTypeLocator(new TypeLocator() {
            @Override
            public Class<?> findType(String typeName) {
                throw new SpelEvaluationException(SpelMessage.TYPE_NOT_FOUND, typeName);
            }
        });

        // Block all method calls
        ctx.setMethodResolvers(Collections.<MethodResolver>singletonList(
            new MethodResolver() {
                @Override
                public MethodExecutor resolve(EvaluationContext context, Object targetObject,
                        String name, List<TypeDescriptor> argumentTypes) throws AccessException {
                    throw new AccessException("Method invocation is not allowed in this context");
                }
            }
        ));

        // Block all constructor calls — prevents new java.lang.ProcessBuilder(...)
        ctx.setConstructorResolvers(Collections.<ConstructorResolver>singletonList(
            new ConstructorResolver() {
                @Override
                public ConstructorExecutor resolve(EvaluationContext context, String typeName,
                        List<TypeDescriptor> argumentTypes) throws AccessException {
                    throw new AccessException("Constructor invocation is not allowed in this context");
                }
            }
        ));

        return ctx;
    }

    /**
     * SpEL endpoint — restricted to prevent RCE.
     * http://localhost:8080/spel/vuln/?expression=xxx.
     */
    @GetMapping("/spel/vuln")
    public String rce(String expression) {
        ExpressionParser parser = new SpelExpressionParser();
        // Restricted context: no type references, no method calls, no constructors
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

