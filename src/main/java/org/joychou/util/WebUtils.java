package org.joychou.util;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import java.io.*;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Pattern;

import com.google.common.base.Preconditions;
import org.springframework.web.util.HtmlUtils;

public class WebUtils {

    // Get request body.
    public static String getRequestBody(HttpServletRequest request) throws IOException {
        InputStream in = request.getInputStream();
        return convertStreamToString(in);
    }

    // https://stackoverflow.com/questions/309424/how-do-i-read-convert-an-inputstream-into-a-string-in-java
    public static String convertStreamToString(java.io.InputStream is) {
        java.util.Scanner s = new java.util.Scanner(is).useDelimiter("\\A");
        return s.hasNext() ? s.next() : "";
    }

    public static String getCookieValueByName(HttpServletRequest request, String cookieName) {
        Cookie cookie = org.springframework.web.util.WebUtils.getCookie(request, cookieName);
        return cookie == null ? null : cookie.getValue();
    }


    /**
     * HTML-encode untrusted text before it is written into a text/html response.
     * Only the HTML special characters are encoded, other characters are kept as is.
     */
    public static String escapeHtml(String input) {
        return input == null ? null : HtmlUtils.htmlEscape(input, "UTF-8");
    }


    // Strict JSONP callback: a (dotted) JavaScript identifier only.
    private static final Pattern JSONP_CALLBACK = Pattern.compile("^[A-Za-z_$][A-Za-z0-9_$.]{0,63}$");

    public static boolean isValidJsonpCallback(String callback) {
        return callback != null && JSONP_CALLBACK.matcher(callback).matches();
    }

    // Fixed table of callback function names that may be emitted into JavaScript.
    private static final Map<String, String> ALLOWED_JSONP_CALLBACKS;

    static {
        Map<String, String> m = new HashMap<>();
        m.put("callback", "callback");
        m.put("jsonpCallback", "jsonpCallback");
        m.put("cb", "cb");
        m.put("handle", "handle");
        m.put("test", "test");
        m.put("aa", "aa");
        ALLOWED_JSONP_CALLBACKS = Collections.unmodifiableMap(m);
    }

    /**
     * Resolve a requested JSONP callback to a server-side constant. The request value is only
     * used as a lookup key; the returned string is the literal from the fixed table.
     *
     * @return the allowed callback name, or null if the request value is not in the table
     */
    public static String resolveJsonpCallback(String requested) {
        if (!isValidJsonpCallback(requested)) {
            return null;
        }
        return ALLOWED_JSONP_CALLBACKS.get(requested);
    }

    /**
     * Wrap json into a JSONP response. The callback is written into JavaScript code, so it is
     * resolved to a constant from a fixed table rather than echoed from the request.
     *
     * @throws IllegalArgumentException if the callback is not an allowed callback name
     */
    public static String json2Jsonp(String callback, String jsonStr) {
        String resolved = resolveJsonpCallback(callback);
        if (resolved == null) {
            throw new IllegalArgumentException("Invalid jsonp callback");
        }
        return resolved + "(" + jsonStr + ")";
    }


    public static String getFileExtension(String fullName) {
        Preconditions.checkNotNull(fullName);
        String fileName = (new File(fullName)).getName();
        int dotIndex = fileName.lastIndexOf('.');
        return dotIndex == -1 ? "" : fileName.substring(dotIndex + 1);
    }


    public static String getNameWithoutExtension(String file) {
        Preconditions.checkNotNull(file);
        String fileName = (new File(file)).getName();
        int dotIndex = fileName.lastIndexOf('.');
        return dotIndex == -1 ? fileName : fileName.substring(0, dotIndex);
    }


}
