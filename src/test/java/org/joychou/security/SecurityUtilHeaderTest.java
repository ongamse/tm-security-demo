package org.joychou.security;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

public class SecurityUtilHeaderTest {

    @Test
    public void stripsCrLfAndControlChars() {
        assertEquals("abSet-Cookie: x=1", SecurityUtil.safeHeaderValue("ab\r\nSet-Cookie: x=1"));
        assertEquals("ab", SecurityUtil.safeHeaderValue("a\u0000b"));
        assertEquals("ab", SecurityUtil.safeHeaderValue("a" + (char) 0x2028 + "b" + (char) 0x2029 + ""));
    }

    @Test
    public void stripsDelAndC1ControlChars() {
        assertEquals("ab", SecurityUtil.safeHeaderValue("a" + (char) 0x7F + "b" + (char) 0x85));
        assertEquals("ab", SecurityUtil.safeHeaderValue("a\nb\r"));
    }

    @Test
    public void keepsNormalValues() {
        assertEquals("http://test.joychou.org/a?b=c d\te",
                SecurityUtil.safeHeaderValue("http://test.joychou.org/a?b=c d\te"));
        assertNull(SecurityUtil.safeHeaderValue(null));
    }
}
