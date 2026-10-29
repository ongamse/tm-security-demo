package org.joychou.controller;

import org.springframework.web.util.HtmlUtils;
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
     * Fixed, pre-defined expressions selectable by key. The expression strings handed to the
     * parser are compile-time constants; request data is only used as a lookup key.
     * http://localhost:8080/spel/vuln?expression=hello
     */
    @GetMapping("/spel/vuln")
    public String rce(String expression) {
        if (expression == null) {
            return "Bad boy. I got u.";
        }
        String fixed;
        switch (expression) {
            case "hello": fixed = "'hello'.toUpperCase()"; break;
            case "length": fixed = "'hello'.length()"; break;
            case "sum": fixed = "1 + 2"; break;
            default: return "Bad boy. I got u.";
        }
        ExpressionParser parser = new SpelExpressionParser();
        EvaluationContext context = SimpleEvaluationContext.forReadOnlyDataBinding().build();
        Object value = parser.parseExpression(fixed).getValue(context);
        return HtmlUtils.htmlEscape(String.valueOf(value));
    }

    public static void main(String[] args) {
        ExpressionParser parser = new SpelExpressionParser();
        String expression = "T(java.lang.Runtime).getRuntime().exec(\"open -a Calculator\")";
        String result = parser.parseExpression(expression).getValue().toString();
        System.out.println(result);
    }
}

