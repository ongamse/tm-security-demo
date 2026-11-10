package org.joychou.security;

import org.junit.Test;

import java.math.BigDecimal;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

public class ArithmeticEvaluatorTest {

    @Test
    public void evaluatesPlainArithmetic() {
        assertEquals(0, new BigDecimal("14").compareTo(ArithmeticEvaluator.evaluate("2 + 3 * 4")));
        assertEquals(0, new BigDecimal("20").compareTo(ArithmeticEvaluator.evaluate("(2 + 3) * 4")));
        assertEquals(0, new BigDecimal("-1").compareTo(ArithmeticEvaluator.evaluate("-4 % 3")));
    }

    @Test
    public void rejectsAnythingElse() {
        assertNull(ArithmeticEvaluator.evaluate(null));
        assertNull(ArithmeticEvaluator.evaluate(""));
        assertNull(ArithmeticEvaluator.evaluate("\"id\".execute()"));
        assertNull(ArithmeticEvaluator.evaluate("T(java.lang.Runtime).getRuntime()"));
        assertNull(ArithmeticEvaluator.evaluate("1 +"));
        assertNull(ArithmeticEvaluator.evaluate("(1"));
        assertNull(ArithmeticEvaluator.evaluate("1/0"));
    }
}
