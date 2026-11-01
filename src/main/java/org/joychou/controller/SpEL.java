package org.joychou.controller;

import org.springframework.expression.Expression;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.HtmlUtils;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;


/**
 * SpEL endpoint. Request data is never parsed as an expression; it only selects one of the
 * constant, pre-compiled expressions below.
 *
 * @author JoyChou @2019-01-17
 */
@RestController
public class SpEL {

    private static final Map<String, Expression> ALLOWED;

    static {
        ExpressionParser parser = new SpelExpressionParser();
        Map<String, Expression> m = new HashMap<>();
        m.put("sum", parser.parseExpression("1 + 2"));
        m.put("product", parser.parseExpression("6 * 7"));
        m.put("greeting", parser.parseExpression("'Hello ' + 'World'"));
        ALLOWED = Collections.unmodifiableMap(m);
    }

    /**
     * http://localhost:8080/spel/vuln?expression=sum
     * expression is a key: sum | product | greeting
     */
    @GetMapping("/spel/vuln")
    public String rce(String expression) {
        Expression compiled = expression == null ? null : ALLOWED.get(expression);
        if (compiled == null) {
            return "Bad boy. I got u.";
        }
        // Constant literal-only expressions: no type, bean, method or property access is possible.
        Object value = compiled.getValue();
        return HtmlUtils.htmlEscape(String.valueOf(value));
    }
}
