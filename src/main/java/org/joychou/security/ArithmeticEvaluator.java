package org.joychou.security;

import java.math.BigDecimal;
import java.math.MathContext;

/**
 * Tiny recursive-descent evaluator for plain arithmetic: decimal numbers, + - * / %, unary +/-
 * and parentheses. It is a parser of its own, so the request string is never handed to a script
 * or expression engine; callers only get back the computed number.
 */
public final class ArithmeticEvaluator {

    private static final int MAX_LENGTH = 100;
    private static final int MAX_DEPTH = 20;

    private final String src;
    private int pos;
    private int depth;

    private ArithmeticEvaluator(String src) {
        this.src = src;
    }

    /**
     * @param expression untrusted arithmetic expression
     * @return the numeric result, or null when the input is not a well-formed arithmetic expression
     *         (or the computation fails, e.g. division by zero)
     */
    public static BigDecimal evaluate(String expression) {
        if (null == expression || expression.isEmpty() || expression.length() > MAX_LENGTH) {
            return null;
        }
        try {
            ArithmeticEvaluator ev = new ArithmeticEvaluator(expression);
            BigDecimal value = ev.parseExpression();
            ev.skipSpaces();
            if (ev.pos != ev.src.length()) {
                return null;
            }
            return value;
        } catch (IllegalArgumentException | ArithmeticException e) {
            return null;
        }
    }

    private BigDecimal parseExpression() {
        BigDecimal left = parseTerm();
        while (true) {
            skipSpaces();
            if (accept('+')) {
                left = left.add(parseTerm(), MathContext.DECIMAL64);
            } else if (accept('-')) {
                left = left.subtract(parseTerm(), MathContext.DECIMAL64);
            } else {
                return left;
            }
        }
    }

    private BigDecimal parseTerm() {
        BigDecimal left = parseFactor();
        while (true) {
            skipSpaces();
            if (accept('*')) {
                left = left.multiply(parseFactor(), MathContext.DECIMAL64);
            } else if (accept('/')) {
                left = left.divide(parseFactor(), MathContext.DECIMAL64);
            } else if (accept('%')) {
                left = left.remainder(parseFactor(), MathContext.DECIMAL64);
            } else {
                return left;
            }
        }
    }

    private BigDecimal parseFactor() {
        skipSpaces();
        if (accept('-')) {
            return parseFactor().negate();
        }
        if (accept('+')) {
            return parseFactor();
        }
        if (accept('(')) {
            if (++depth > MAX_DEPTH) {
                throw new IllegalArgumentException("too deep");
            }
            BigDecimal inner = parseExpression();
            skipSpaces();
            if (!accept(')')) {
                throw new IllegalArgumentException("missing )");
            }
            depth--;
            return inner;
        }
        return parseNumber();
    }

    private BigDecimal parseNumber() {
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
        if (pos == start || (pos - start == 1 && dot)) {
            throw new IllegalArgumentException("number expected");
        }
        // only [0-9.] characters were consumed, so this is a plain decimal literal
        return new BigDecimal(src.substring(start, pos));
    }

    private boolean accept(char c) {
        if (pos < src.length() && src.charAt(pos) == c) {
            pos++;
            return true;
        }
        return false;
    }

    private void skipSpaces() {
        while (pos < src.length() && Character.isWhitespace(src.charAt(pos))) {
            pos++;
        }
    }
}
