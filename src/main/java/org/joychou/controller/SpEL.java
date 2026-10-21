package org.joychou.controller;

import org.springframework.expression.EvaluationContext;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.SimpleEvaluationContext;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;


/**
 * SpEL Injection
 *
 * @author JoyChou @2019-01-17
 */
@RestController
public class SpEL {

    /**
     * SpEL evaluation endpoint.
     * Uses SimpleEvaluationContext to prevent type references and RCE.
     */
    @GetMapping("/spel/vuln")
    public String rce(String expression) {
        ExpressionParser parser = new SpelExpressionParser();
        EvaluationContext context = SimpleEvaluationContext.forReadOnlyDataBinding().build();
        return parser.parseExpression(expression).getValue(context, String.class);
    }

    public static void main(String[] args) {
        ExpressionParser parser = new SpelExpressionParser();
        EvaluationContext context = SimpleEvaluationContext.forReadOnlyDataBinding().build();
        String expression = "'Hello World'";
        String result = parser.parseExpression(expression).getValue(context, String.class);
        System.out.println(result);
    }
}

