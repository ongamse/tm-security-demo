package org.joychou.security;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

public class SecurityUtilRedirectTest {

    @Test
    public void allowsSameOriginRelativePath() {
        assertEquals("/urlRedirect/test?a=b", SecurityUtil.safeRedirectUrl("/urlRedirect/test?a=b"));
    }

    @Test
    public void rejectsOpenRedirectTricks() {
        assertNull(SecurityUtil.safeRedirectUrl(null));
        assertNull(SecurityUtil.safeRedirectUrl(""));
        assertNull(SecurityUtil.safeRedirectUrl("//evil.com"));
        assertNull(SecurityUtil.safeRedirectUrl("/\\evil.com"));
        assertNull(SecurityUtil.safeRedirectUrl("http://evil.com\\@www.joychou.org/"));
        assertNull(SecurityUtil.safeRedirectUrl("/a\r\nSet-Cookie: x=1"));
        assertNull(SecurityUtil.safeRedirectUrl("javascript:alert(1)"));
        assertNull(SecurityUtil.safeRedirectUrl("evil.com"));
    }

    @Test
    public void safeHttpUrlSyntax() {
        assertTrue(SecurityUtil.isSafeHttpUrl("https://a.joychou.org/x?y=1"));
        assertFalse(SecurityUtil.isSafeHttpUrl("http://evil.com\\www.joychou.org/a.html"));
        assertFalse(SecurityUtil.isSafeHttpUrl("http://evil.com@www.joychou.org/"));
        assertFalse(SecurityUtil.isSafeHttpUrl("http:///a"));
        assertFalse(SecurityUtil.isSafeHttpUrl("ftp://a.joychou.org"));
        assertFalse(SecurityUtil.isSafeHttpUrl(null));
    }
}
