package org.joychou.controller;

import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.SimpleEvaluationContext;
import org.springframework.expression.EvaluationContext;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;


/**
 * SpEL Expression Evaluation
 *
 * @author JoyChou @2019-01-17
 */
@RestController
public class SpEL {

    /**
     * SpEL evaluation endpoint using SimpleEvaluationContext to prevent RCE.
     * SimpleEvaluationContext restricts expressions to data binding only,
     * blocking T() type references, bean references, and constructors.
     * http://localhost:8080/spel/vuln/?expression=xxx
     */
    @GetMapping("/spel/vuln")
    public String rce(String expression) {
        ExpressionParser parser = new SpelExpressionParser();
        // Use SimpleEvaluationContext to prevent arbitrary code execution via SpEL
        EvaluationContext context = SimpleEvaluationContext.forReadOnlyDataBinding().build();
        return parser.parseExpression(expression).getValue(context, String.class);
    }

    public static void main(String[] args) {
        ExpressionParser parser = new SpelExpressionParser();
        // SimpleEvaluationContext prevents RCE through SpEL expressions
        EvaluationContext context = SimpleEvaluationContext.forReadOnlyDataBinding().build();
        String expression = "1 + 1";
        String result = parser.parseExpression(expression).getValue(context, String.class);
        System.out.println(result);
    }
}

