package org.joychou.security;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertFalse;

public class SecurityUtilUrlTest {

    @Test
    public void parsesWellFormedHttpUrl() {
        SecurityUtil.ParsedUrl p = SecurityUtil.parseHttpUrl("HTTPS://Example.COM:8443/a/b?x=1#frag");
        assertNotNull(p);
        assertEquals("https", p.getScheme());
        assertEquals("example.com", p.getHost());
        assertEquals(8443, p.getPort());
        assertEquals("/a/b?x=1", p.getFile());
    }

    @Test
    public void rejectsMalformedOrDangerousUrls() {
        assertNull(SecurityUtil.parseHttpUrl(null));
        assertNull(SecurityUtil.parseHttpUrl("file:///etc/passwd"));
        assertNull(SecurityUtil.parseHttpUrl("http://evil.com\\@www.joychou.org/"));
        assertNull(SecurityUtil.parseHttpUrl("http://user@evil.com/"));
        assertNull(SecurityUtil.parseHttpUrl("http://example.com:99999/"));
        assertNull(SecurityUtil.parseHttpUrl("http://example.com/a b"));
        assertNull(SecurityUtil.parseHttpUrl("http://example.com/\r\nHost: x"));
        assertNull(SecurityUtil.parseHttpUrl("http:///path"));
    }

    @Test
    public void gethostUsesStrictParser() {
        assertEquals("www.joychou.org", SecurityUtil.gethost("http://www.JoyChou.org/a.html"));
        assertEquals("", SecurityUtil.gethost("http://evil.com\\@www.joychou.org/a.html"));
        assertEquals("", SecurityUtil.gethost("not a url"));
        assertFalse(SecurityUtil.isSafeUrlSyntax("javascript:alert(1)"));
        assertTrue(SecurityUtil.isSafeUrlSyntax("http://example.com/"));
    }

    @Test
    public void safeRedirectUrlRelativePaths() {
        assertEquals("/index", SecurityUtil.safeRedirectUrl("/index"));
        assertNull(SecurityUtil.safeRedirectUrl("//evil.com"));
        assertNull(SecurityUtil.safeRedirectUrl("/\\evil.com"));
    }

    @Test
    public void jdbcUrlRejectsInvalidInput() {
        assertNull(SecurityUtil.safeJdbcUrl(null, "postgresql"));
        assertNull(SecurityUtil.safeJdbcUrl("jdbc:postgresql://127.0.0.1/db", "postgresql"));
        assertNull(SecurityUtil.safeJdbcUrl("jdbc:postgresql://example.com/db?socketFactory=x", "postgresql"));
        assertNull(SecurityUtil.safeJdbcUrl("jdbc:db2://example.com/db", "postgresql"));
    }

    @Test
    public void matchJdbcUrlOnlyReturnsConfiguredConstants() {
        assertNull(SecurityUtil.matchJdbcUrl(null, "postgresql"));
        assertNull(SecurityUtil.matchJdbcUrl("jdbc:postgresql://127.0.0.1/db", "postgresql"));
        assertNull(SecurityUtil.matchJdbcUrl("jdbc:postgresql://example.com/db?socketFactory=x", "postgresql"));
        assertNull(SecurityUtil.matchJdbcUrl("jdbc:db2://example.com/db", "postgresql"));
        // Nothing configured in a plain unit test: no request value is ever echoed back.
        new org.joychou.config.WebConfig().setJdbcAllowedUrls(new String[0]);
        assertNull(SecurityUtil.matchJdbcUrl("jdbc:postgresql://example.com/db", "postgresql"));
    }
}
