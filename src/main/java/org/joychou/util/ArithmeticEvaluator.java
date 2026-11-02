package org.joychou.util;

import java.math.BigDecimal;
import java.math.RoundingMode;

/**
 * Tiny strict evaluator for literal arithmetic / comparison text. It is a plain recursive-descent
 * parser over digits and operators: no identifiers, no reflection, no script or expression engine.
 *
 * <pre>
 * comparison = sum [ ("&lt;" | "&gt;" | "&lt;=" | "&gt;=" | "==" | "!=") sum ]
 * sum        = product { ("+" | "-") product }
 * product    = factor { ("*" | "/" | "%") factor }
 * factor     = "-" factor | "(" sum ")" | number
 * </pre>
 */
public final class ArithmeticEvaluator {

    private static final int MAX_LENGTH = 128;

    private final String src;
    private int pos;

    private ArithmeticEvaluator(String src) {
        this.src = src;
    }

    /**
     * Evaluate the text.
     *
     * @param text untrusted expression text
     * @return the plain decimal result, or "true"/"false" for a comparison
     * @throws IllegalArgumentException (or ArithmeticException / NumberFormatException) when the text
     *                                  is not a valid expression
     */
    public static String evaluate(String text) {
        if (text == null) {
            throw new IllegalArgumentException("null expression");
        }
        String compact = text.replaceAll("\\s+", "");
        if (compact.isEmpty() || compact.length() > MAX_LENGTH) {
            throw new IllegalArgumentException("bad length");
        }
        ArithmeticEvaluator evaluator = new ArithmeticEvaluator(compact);
        String result = evaluator.comparison();
        if (evaluator.pos != compact.length()) {
            throw new IllegalArgumentException("unexpected input");
        }
        return result;
    }

    private String comparison() {
        BigDecimal left = sum();
        String op = readComparisonOperator();
        if (op == null) {
            return left.toPlainString();
        }
        BigDecimal right = sum();
        int cmp = left.compareTo(right);
        boolean result;
        switch (op) {
            case "<":
                result = cmp < 0;
                break;
            case ">":
                result = cmp > 0;
                break;
            case "<=":
                result = cmp <= 0;
                break;
            case ">=":
                result = cmp >= 0;
                break;
            case "==":
                result = cmp == 0;
                break;
            case "!=":
                result = cmp != 0;
                break;
            default:
                throw new IllegalArgumentException("bad operator");
        }
        return Boolean.toString(result);
    }

    private String readComparisonOperator() {
        if (pos >= src.length()) {
            return null;
        }
        char c = src.charAt(pos);
        char next = pos + 1 < src.length() ? src.charAt(pos + 1) : '\0';
        if (c == '<' || c == '>') {
            if (next == '=') {
                pos += 2;
                return c == '<' ? "<=" : ">=";
            }
            pos++;
            return c == '<' ? "<" : ">";
        }
        if ((c == '=' || c == '!') && next == '=') {
            pos += 2;
            return c == '=' ? "==" : "!=";
        }
        return null;
    }

    private BigDecimal sum() {
        BigDecimal v = product();
        while (pos < src.length() && (src.charAt(pos) == '+' || src.charAt(pos) == '-')) {
            char op = src.charAt(pos++);
            BigDecimal r = product();
            v = op == '+' ? v.add(r) : v.subtract(r);
        }
        return v;
    }

    private BigDecimal product() {
        BigDecimal v = factor();
        while (pos < src.length()
                && (src.charAt(pos) == '*' || src.charAt(pos) == '/' || src.charAt(pos) == '%')) {
            char op = src.charAt(pos++);
            BigDecimal r = factor();
            if (op == '*') {
                v = v.multiply(r);
            } else if (op == '/') {
                v = v.divide(r, 10, RoundingMode.HALF_UP);
            } else {
                v = v.remainder(r);
            }
        }
        return v;
    }

    private BigDecimal factor() {
        if (pos >= src.length()) {
            throw new IllegalArgumentException("unexpected end");
        }
        char c = src.charAt(pos);
        if (c == '-') {
            pos++;
            return factor().negate();
        }
        if (c == '(') {
            pos++;
            BigDecimal v = sum();
            if (pos >= src.length() || src.charAt(pos) != ')') {
                throw new IllegalArgumentException("missing )");
            }
            pos++;
            return v;
        }
        int start = pos;
        while (pos < src.length() && ((src.charAt(pos) >= '0' && src.charAt(pos) <= '9') || src.charAt(pos) == '.')) {
            pos++;
        }
        if (start == pos) {
            throw new IllegalArgumentException("number expected");
        }
        return new BigDecimal(src.substring(start, pos));
    }
}
