package org.joychou.controller;

import org.springframework.expression.ConstructorResolver;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.PropertyAccessor;
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
     * Predefined expressions. The "expression" request parameter only selects one of these; the
     * attacker-supplied data is exposed to the expression solely as the variable #input.
     * http://localhost:8080/spel/vuln?expression=upper&value=hello
     */
    @GetMapping("/spel/vuln")
    public String rce(String expression, String value) {
        String fixedExpression = selectExpression(expression);
        if (fixedExpression == null) {
            return "Bad boy. I got u.";
        }
        ExpressionParser parser = new SpelExpressionParser();
        // No type references (T(...)), no constructors, no bean/property access.
        StandardEvaluationContext context = new StandardEvaluationContext();
        context.setTypeLocator(typeName -> {
            throw new SpelEvaluationException(SpelMessage.TYPE_NOT_FOUND, typeName);
        });
        context.setConstructorResolvers(Collections.<ConstructorResolver>emptyList());
        context.setPropertyAccessors(Collections.<PropertyAccessor>emptyList());
        context.setVariable("input", value == null ? "" : value);
        return HtmlUtils.htmlEscape(String.valueOf(parser.parseExpression(fixedExpression).getValue(context)));
    }

    private static String selectExpression(String selector) {
        if (selector == null) {
            return null;
        }
        switch (selector.trim()) {
            case "length":
                return "#input.length()";
            case "upper":
                return "#input.toUpperCase()";
            case "lower":
                return "#input.toLowerCase()";
            case "trim":
                return "#input.trim()";
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

