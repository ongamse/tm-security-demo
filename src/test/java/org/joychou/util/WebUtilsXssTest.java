package org.joychou.util;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class WebUtilsXssTest {

    @Test
    public void acceptsIdentifierCallbacks() {
        assertTrue(WebUtils.isValidJsonpCallback("test"));
        assertTrue(WebUtils.isValidJsonpCallback("_cb$1"));
        assertTrue(WebUtils.isValidJsonpCallback("window.app.cb"));
        assertEquals("cb({\"a\":1})", WebUtils.json2Jsonp("cb", "{\"a\":1}"));
    }

    @Test
    public void rejectsNonIdentifierCallbacks() {
        assertFalse(WebUtils.isValidJsonpCallback(null));
        assertFalse(WebUtils.isValidJsonpCallback(""));
        assertFalse(WebUtils.isValidJsonpCallback("1abc"));
        assertFalse(WebUtils.isValidJsonpCallback("alert(1);//"));
        assertFalse(WebUtils.isValidJsonpCallback("<script>alert(1)</script>"));
        assertFalse(WebUtils.isValidJsonpCallback("a\nb"));
        StringBuilder sb = new StringBuilder("a");
        for (int i = 0; i < 64; i++) {
            sb.append('b');
        }
        assertFalse(WebUtils.isValidJsonpCallback(sb.toString()));
    }

    @Test(expected = IllegalArgumentException.class)
    public void json2JsonpThrowsOnInvalidCallback() {
        WebUtils.json2Jsonp("alert(1)//", "{}");
    }

    @Test
    public void escapeHtmlEncodesSpecials() {
        assertEquals("&lt;script&gt;alert(1)&lt;/script&gt;", WebUtils.escapeHtml("<script>alert(1)</script>"));
    }
}
