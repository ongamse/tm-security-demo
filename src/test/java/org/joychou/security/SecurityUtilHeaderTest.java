package org.joychou.security;

import org.joychou.config.WebConfig;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.Arrays;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

public class SecurityUtilHeaderTest {

    private ArrayList<String> oldSafe;
    private ArrayList<String> oldBlock;

    @SuppressWarnings("unchecked")
    private static ArrayList<String> swap(String field, ArrayList<String> value) throws Exception {
        Field f = WebConfig.class.getDeclaredField(field);
        f.setAccessible(true);
        ArrayList<String> old = (ArrayList<String>) f.get(null);
        f.set(null, value);
        return old;
    }

    @Before
    public void setUp() throws Exception {
        oldSafe = swap("safeDomains", new ArrayList<>(Arrays.asList("joychou.org", "localhost")));
        oldBlock = swap("blockDomains", new ArrayList<>(Arrays.asList("evil.joychou.org")));
    }

    @After
    public void tearDown() throws Exception {
        swap("safeDomains", oldSafe);
        swap("blockDomains", oldBlock);
    }

    @Test
    public void matchAllowedOriginReturnsAllowlistedConstant() {
        assertEquals("https://joychou.org", SecurityUtil.matchAllowedOrigin("https://joychou.org"));
        assertEquals("http://www.joychou.org", SecurityUtil.matchAllowedOrigin("http://www.joychou.org"));
        assertEquals("http://localhost:8080", SecurityUtil.matchAllowedOrigin("http://localhost:8080"));
    }

    @Test
    public void matchAllowedOriginRejectsOthers() {
        assertNull(SecurityUtil.matchAllowedOrigin(null));
        assertNull(SecurityUtil.matchAllowedOrigin("null"));
        assertNull(SecurityUtil.matchAllowedOrigin("https://evil.com"));
        assertNull(SecurityUtil.matchAllowedOrigin("https://evil.joychou.org"));
        assertNull(SecurityUtil.matchAllowedOrigin("https://joychou.org.evil.com"));
        assertNull(SecurityUtil.matchAllowedOrigin("https://joychou.org/path"));
        assertNull(SecurityUtil.matchAllowedOrigin("https://joychou.org\r\nX-Injected: 1"));
    }

    @Test
    public void matchCorsOriginIsExactConstantLookup() throws Exception {
        Field f = WebConfig.class.getDeclaredField("corsAllowedOrigins");
        f.setAccessible(true);
        Object old = f.get(null);
        f.set(null, new String[]{"https://joychou.org", " http://localhost:8080 "});
        try {
            assertEquals("https://joychou.org", SecurityUtil.matchCorsOrigin("https://joychou.org"));
            assertEquals("http://localhost:8080", SecurityUtil.matchCorsOrigin("http://localhost:8080"));
            assertNull(SecurityUtil.matchCorsOrigin(null));
            assertNull(SecurityUtil.matchCorsOrigin("null"));
            assertNull(SecurityUtil.matchCorsOrigin("*"));
            assertNull(SecurityUtil.matchCorsOrigin("https://www.joychou.org"));
            assertNull(SecurityUtil.matchCorsOrigin("https://sub.joychou.org"));
            assertNull(SecurityUtil.matchCorsOrigin("https://joychou.org.evil.com"));
            assertNull(SecurityUtil.matchCorsOrigin("https://joychou.org\r\nX-Injected: 1"));
        } finally {
            f.set(null, old);
        }
    }

    @Test
    public void matchCorsOriginRejectsEverythingWhenUnconfigured() {
        assertNull(SecurityUtil.matchCorsOrigin("https://joychou.org"));
    }

    @Test
    public void safeRedirectLocationIsConstant() {
        assertEquals("/", SecurityUtil.safeRedirectLocation("/index?a=1"));
        assertEquals("https://www.joychou.org/", SecurityUtil.safeRedirectLocation("https://www.joychou.org/a/b?x=1"));
        assertNull(SecurityUtil.safeRedirectLocation("https://evil.com/"));
        assertNull(SecurityUtil.safeRedirectLocation("//evil.com"));
        assertNull(SecurityUtil.safeRedirectLocation(null));
    }
}
