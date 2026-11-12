package org.joychou.controller;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

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
import org.springframework.web.util.HtmlUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;


/**
 * SpEL Injection
 *
 * @author JoyChou @2019-01-17
 */
@RestController
public class SpEL {

    /**
     * Server-side table of vetted expressions (literals, operators and inline collections only).
     * The request value can only select a row; the expression that is parsed is the table's own string.
     */
    private static final Map<String, String> ALLOWED_EXPRESSIONS;

    static {
        Map<String, String> table = new LinkedHashMap<String, String>();
        table.put("1+1", "1+1");
        table.put("2*3", "2*3");
        table.put("10-4", "10-4");
        table.put("{1,2,3}", "{1,2,3}");
        ALLOWED_EXPRESSIONS = Collections.unmodifiableMap(table);
    }

    /**
     * SpEL demo: only expressions of the server-side table can be evaluated.
     * http://localhost:8080/spel/vuln?expression=1%2B1
     */
    @GetMapping("/spel/vuln")
    public String rce(String expression) {
        for (Map.Entry<String, String> entry : ALLOWED_EXPRESSIONS.entrySet()) {
            if (entry.getKey().equals(expression)) {
                ExpressionParser parser = new SpelExpressionParser();
                return HtmlUtils.htmlEscape(String.valueOf(
                        parser.parseExpression(entry.getValue()).getValue(restrictedContext())));
            }
        }
        return "Expression not allowed!!";
    }

    /**
     * Locked-down context (APIs available since Spring 3.x): no type references (T(...)),
     * no constructors, no method calls, no property access and no bean references.
     * Only literals, operators and inline collections can be evaluated.
     */
    private static EvaluationContext restrictedContext() {
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
        context.setBeanResolver(null);
        return context;
    }
}
