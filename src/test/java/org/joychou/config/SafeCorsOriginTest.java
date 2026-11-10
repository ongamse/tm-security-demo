package org.joychou.config;

import org.joychou.security.SecurityUtil;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.util.ArrayList;
import java.util.Arrays;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

/**
 * Lives in the config package to reach the package-private WebConfig domain setters.
 */
public class SafeCorsOriginTest {

    private final WebConfig webConfig = new WebConfig();

    @Before
    public void setUp() {
        webConfig.setSafeDomains(new ArrayList<>(Arrays.asList("joychou.org", "localhost")));
        webConfig.setBlockDomains(new ArrayList<>(Arrays.asList("evil.joychou.org")));
    }

    @After
    public void tearDown() {
        webConfig.setSafeDomains(new ArrayList<String>());
        webConfig.setBlockDomains(new ArrayList<String>());
    }

    @Test
    public void allowsTrustedOrigins() {
        assertEquals("https://joychou.org", SecurityUtil.safeCorsOrigin("https://joychou.org"));
        assertEquals("http://a.joychou.org:8080", SecurityUtil.safeCorsOrigin("http://a.joychou.org:8080"));
        assertEquals("http://localhost:8080", SecurityUtil.safeCorsOrigin("http://localhost:8080"));
    }

    @Test
    public void allowlistReturnsConstantElement() {
        assertEquals("https://joychou.org", SecurityUtil.allowedCorsOrigin("https://joychou.org"));
        assertEquals("https://joychou.org", SecurityUtil.allowedCorsOrigin("HTTPS://JOYCHOU.ORG"));
        assertEquals("http://localhost:8080", SecurityUtil.allowedCorsOrigin("http://localhost:8080"));
    }

    @Test
    public void allowlistRejectsEverythingElse() {
        assertNull(SecurityUtil.allowedCorsOrigin(null));
        assertNull(SecurityUtil.allowedCorsOrigin("null"));
        assertNull(SecurityUtil.allowedCorsOrigin("*"));
        assertNull(SecurityUtil.allowedCorsOrigin("https://evil.com"));
        assertNull(SecurityUtil.allowedCorsOrigin("http://joychou.org"));
        assertNull(SecurityUtil.allowedCorsOrigin("https://a.joychou.org"));
        assertNull(SecurityUtil.allowedCorsOrigin("https://joychou.org\r\nX-Evil: 1"));
    }

    @Test
    public void explicitOriginsHaveNoWildcard() {
        for (String o : SecurityUtil.corsAllowedOrigins()) {
            assertEquals(o, SecurityUtil.allowedCorsOrigin(o));
            org.junit.Assert.assertFalse(o.contains("*"));
        }
    }

    @Test
    public void rejectsUntrustedOrigins() {
        assertNull(SecurityUtil.safeCorsOrigin(null));
        assertNull(SecurityUtil.safeCorsOrigin("null"));
        assertNull(SecurityUtil.safeCorsOrigin("*"));
        assertNull(SecurityUtil.safeCorsOrigin("https://evil.com"));
        assertNull(SecurityUtil.safeCorsOrigin("https://joychou.org.evil.com"));
        assertNull(SecurityUtil.safeCorsOrigin("https://evil.joychou.org"));
        assertNull(SecurityUtil.safeCorsOrigin("https://joychou.org@evil.com"));
        assertNull(SecurityUtil.safeCorsOrigin("https://joychou.org/path"));
        assertNull(SecurityUtil.safeCorsOrigin("https://joychou.org\r\nX-Evil: 1"));
    }
}
