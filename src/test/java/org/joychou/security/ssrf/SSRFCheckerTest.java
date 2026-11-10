package org.joychou.security.ssrf;

import org.joychou.security.SecurityUtil;
import org.junit.Test;

import java.net.URI;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * Offline tests: only IP literals are used, so no DNS lookup is needed.
 */
public class SSRFCheckerTest {

    private static void assertRejected(String url) {
        try {
            SSRFChecker.requireSafeUrl(url);
            fail("Expected SSRFException for " + url);
        } catch (SSRFException expected) {
            // ok
        }
    }

    @Test
    public void rejectsNonHttpSchemes() {
        assertRejected("file:///etc/passwd");
        assertRejected("jar:http://8.8.8.8/a.jar!/");
        assertRejected("ftp://8.8.8.8/");
        assertRejected(null);
    }

    @Test
    public void rejectsInternalAddresses() {
        assertRejected("http://127.0.0.1/");
        assertRejected("http://0.0.0.0/");
        assertRejected("http://10.1.2.3/");
        assertRejected("http://172.16.0.1/");
        assertRejected("http://192.168.1.1/");
        assertRejected("http://169.254.169.254/latest/meta-data/");
        assertRejected("http://100.100.100.200/");
        assertRejected("http://[::1]/");
        assertRejected("http://[::ffff:127.0.0.1]/");
        assertRejected("http://012.0.0.1/");
    }

    @Test
    public void acceptsPublicAddress() {
        assertNotNull(SSRFChecker.requireSafeUrl("https://8.8.8.8/dns"));
    }

    @Test
    public void safeUriIsRebuiltFromValidatedParts() {
        URI uri = SSRFChecker.requireSafeUri(" HTTPS://8.8.8.8:8443/a%20b?x=1&y=%2F#frag ");
        assertEquals("https://8.8.8.8:8443/a%20b?x=1&y=%2F", uri.toString());
        assertEquals("http://8.8.8.8", SSRFChecker.requireSafeUri("http://8.8.8.8").toString());
    }

    @Test
    public void safeUriRejectsTricks() {
        for (String url : new String[]{"http://8.8.8.8@127.0.0.1/", "http://127.0.0.1\\@8.8.8.8/",
                "http://8.8.8.8/a\r\nHost: x", "http:///a", "http://", "file:///etc/passwd",
                "http://10.0.0.1/", "http://169.254.169.254/", "//8.8.8.8/", "8.8.8.8", ""}) {
            try {
                SSRFChecker.requireSafeUri(url);
                fail("Expected SSRFException for " + url);
            } catch (SSRFException expected) {
                // ok
            }
        }
    }

    @Test
    public void parseHttpUriOnlyAcceptsHttpUrls() {
        assertNotNull(SSRFChecker.parseHttpUri("http://example.com/x"));
        assertNull(SSRFChecker.parseHttpUri("ftp://example.com/"));
        assertNull(SSRFChecker.parseHttpUri("http://exa mple.com/"));
        assertNull(SSRFChecker.parseHttpUri(null));
        assertEquals("", SecurityUtil.gethost("javascript:alert(1)"));
        assertEquals("example.com", SecurityUtil.gethost("http://Example.com/x"));
    }

    @Test
    public void jdbcUrlIsRebuiltWithValidatedAddress() {
        assertEquals("jdbc:postgresql://8.8.8.8:5432/db",
                SecurityUtil.requireSafeJdbcUrl("jdbc:postgresql://8.8.8.8:5432/db", "postgresql"));
        assertEquals("jdbc:db2://8.8.8.8", SecurityUtil.requireSafeJdbcUrl("jdbc:db2://8.8.8.8", "db2"));
        try {
            SecurityUtil.requireSafeJdbcUrl("jdbc:postgresql://10.0.0.1/db", "postgresql");
            fail("Expected SSRFException");
        } catch (SSRFException expected) {
            // ok
        }
        try {
            SecurityUtil.requireSafeJdbcUrl("jdbc:postgresql://8.8.8.8/db?loggerLevel=DEBUG", "postgresql");
            fail("Expected IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            // ok
        }
    }

    @Test
    public void internalIpByUrl() {
        assertTrue(SSRFChecker.isInternalIpByUrl("http://127.0.0.1/"));
        assertTrue(SSRFChecker.isInternalIpByUrl("gopher://8.8.8.8/"));
        assertFalse(SSRFChecker.isInternalIpByUrl("http://8.8.8.8/"));
    }

    @Test
    public void jdbcUrlValidation() {
        assertTrue(SecurityUtil.isSafeJdbcUrl("jdbc:postgresql://8.8.8.8:5432/db", "postgresql"));
        assertFalse(SecurityUtil.isSafeJdbcUrl("jdbc:postgresql://127.0.0.1:5432/db", "postgresql"));
        assertFalse(SecurityUtil.isSafeJdbcUrl("jdbc:postgresql://169.254.169.254/db", "postgresql"));
        assertFalse(SecurityUtil.isSafeJdbcUrl("jdbc:postgresql://8.8.8.8/db?socketFactory=x&socketFactoryArg=y", "postgresql"));
        assertFalse(SecurityUtil.isSafeJdbcUrl("jdbc:postgresql://8.8.8.8/db", "db2"));
        assertFalse(SecurityUtil.isSafeJdbcUrl("jdbc:mysql://8.8.8.8/db", "postgresql"));
        assertFalse(SecurityUtil.isSafeJdbcUrl(null, "postgresql"));
    }
}
