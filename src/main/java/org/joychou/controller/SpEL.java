package org.joychou.controller;

import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.joychou.util.WebUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.math.BigDecimal;
import java.math.MathContext;


/**
 * SpEL Injection
 *
 * @author JoyChou @2019-01-17
 */
@RestController
public class SpEL {

    private static final int MAX_EXPRESSION_LENGTH = 100;
    private static final int MAX_DEPTH = 20;

    /**
     * Arithmetic expression endpoint.
     * Request text is never handed to an expression engine; it is evaluated by a small
     * hand-written recursive-descent evaluator that only understands numbers, + - * / %,
     * parentheses and a single optional comparison (&lt; &gt; &lt;= &gt;= == !=).
     * http://localhost:8080/spel/vuln/?expression=1%2B2
     */
    @GetMapping("/spel/vuln")
    public String rce(String expression) {
        if (expression == null || expression.length() > MAX_EXPRESSION_LENGTH) {
            return "Bad boy. I got u.";
        }
        try {
            return WebUtils.htmlEncode(new ArithmeticEvaluator(expression).evaluate());
        } catch (IllegalArgumentException | ArithmeticException e) {
            return "Bad boy. I got u.";
        }
    }

    /**
     * Minimal evaluator. Grammar:
     * <pre>
     * expr    := add [ (&lt; | &gt; | &lt;= | &gt;= | == | !=) add ]
     * add     := mul { (+ | -) mul }
     * mul     := unary { (* | / | %) unary }
     * unary   := (+ | -) unary | primary
     * primary := number | ( add )
     * </pre>
     */
    private static final class ArithmeticEvaluator {
        private final String src;
        private int pos = 0;
        private int depth = 0;

        ArithmeticEvaluator(String src) {
            this.src = src;
        }

        String evaluate() {
            BigDecimal left = add();
            skipSpaces();
            String op = null;
            if (pos < src.length()) {
                char c = src.charAt(pos);
                char n = pos + 1 < src.length() ? src.charAt(pos + 1) : '\0';
                if (c == '<' || c == '>') {
                    op = n == '=' ? String.valueOf(c) + "=" : String.valueOf(c);
                } else if ((c == '=' || c == '!') && n == '=') {
                    op = String.valueOf(c) + "=";
                }
            }
            if (op == null) {
                expectEnd();
                return left.stripTrailingZeros().toPlainString();
            }
            pos += op.length();
            BigDecimal right = add();
            expectEnd();
            int cmp = left.compareTo(right);
            boolean result;
            switch (op) {
                case "<":  result = cmp < 0;  break;
                case ">":  result = cmp > 0;  break;
                case "<=": result = cmp <= 0; break;
                case ">=": result = cmp >= 0; break;
                case "==": result = cmp == 0; break;
                default:   result = cmp != 0; break;
            }
            return result ? "true" : "false";
        }

        private void expectEnd() {
            skipSpaces();
            if (pos != src.length()) {
                throw new IllegalArgumentException("unexpected input");
            }
        }

        private void skipSpaces() {
            while (pos < src.length() && src.charAt(pos) == ' ') {
                pos++;
            }
        }

        private BigDecimal add() {
            BigDecimal value = mul();
            while (true) {
                skipSpaces();
                if (pos >= src.length()) {
                    return value;
                }
                char c = src.charAt(pos);
                if (c == '+') {
                    pos++;
                    value = value.add(mul());
                } else if (c == '-') {
                    pos++;
                    value = value.subtract(mul());
                } else {
                    return value;
                }
            }
        }

        private BigDecimal mul() {
            BigDecimal value = unary();
            while (true) {
                skipSpaces();
                if (pos >= src.length()) {
                    return value;
                }
                char c = src.charAt(pos);
                if (c == '*') {
                    pos++;
                    value = value.multiply(unary());
                } else if (c == '/') {
                    pos++;
                    value = value.divide(unary(), MathContext.DECIMAL64);
                } else if (c == '%') {
                    pos++;
                    value = value.remainder(unary());
                } else {
                    return value;
                }
            }
        }

        private BigDecimal unary() {
            skipSpaces();
            if (pos < src.length()) {
                char c = src.charAt(pos);
                if (c == '-' || c == '+') {
                    pos++;
                    enter();
                    try {
                        BigDecimal v = unary();
                        return c == '-' ? v.negate() : v;
                    } finally {
                        depth--;
                    }
                }
            }
            return primary();
        }

        private BigDecimal primary() {
            skipSpaces();
            if (pos >= src.length()) {
                throw new IllegalArgumentException("unexpected end");
            }
            char c = src.charAt(pos);
            if (c == '(') {
                pos++;
                enter();
                try {
                    BigDecimal v = add();
                    skipSpaces();
                    if (pos >= src.length() || src.charAt(pos) != ')') {
                        throw new IllegalArgumentException("missing )");
                    }
                    pos++;
                    return v;
                } finally {
                    depth--;
                }
            }
            return number();
        }

        private BigDecimal number() {
            int start = pos;
            boolean dot = false;
            while (pos < src.length()) {
                char c = src.charAt(pos);
                if (c >= '0' && c <= '9') {
                    pos++;
                } else if (c == '.' && !dot) {
                    dot = true;
                    pos++;
                } else {
                    break;
                }
            }
            String text = src.substring(start, pos);
            if (text.isEmpty() || ".".equals(text)) {
                throw new IllegalArgumentException("number expected");
            }
            return new BigDecimal(text);
        }

        private void enter() {
            if (++depth > MAX_DEPTH) {
                throw new IllegalArgumentException("too deep");
            }
        }
    }

    public static void main(String[] args) {
        ExpressionParser parser = new SpelExpressionParser();
        String expression = "T(java.lang.Runtime).getRuntime().exec(\"open -a Calculator\")";
        String result = parser.parseExpression(expression).getValue().toString();
        System.out.println(result);
    }
}

