package org.joychou.security.ssrf;

import org.joychou.security.SecurityUtil;
import org.junit.Test;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
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
