package org.joychou.security;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class SecurityUtilLogTest {

    @Test
    public void replacesCrLfAndControlChars() {
        assertEquals("a__INFO fake", SecurityUtil.sanitizeForLog("a\r\nINFO fake"));
        assertEquals("a_b", SecurityUtil.sanitizeForLog("a\u0000b"));
        assertEquals("a_b_c", SecurityUtil.sanitizeForLog("a" + (char) 0x2028 + "b" + (char) 0x2029 + "c"));
        assertEquals("a_b_", SecurityUtil.sanitizeForLog("a" + (char) 0x7F + "b" + (char) 0x85));
    }

    @Test
    public void keepsNormalValuesAndHandlesNull() {
        assertEquals("http://a.com/x?y=1", SecurityUtil.sanitizeForLog("http://a.com/x?y=1"));
        assertEquals("null", SecurityUtil.sanitizeForLog(null));
    }

    @Test
    public void truncatesLongValues() {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 5000; i++) {
            sb.append('a');
        }
        String out = SecurityUtil.sanitizeForLog(sb.toString());
        assertTrue(out.length() < 1100);
        assertTrue(out.endsWith("..."));
    }
}
