package org.joychou.util;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import java.io.*;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

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


    // Server-side allowlist of JSONP function names. The requested callback is only
    // used as a lookup key; the emitted function name is the constant map value.
    private static final Map<String, String> JSONP_CALLBACK_ALLOWLIST;

    static {
        Map<String, String> m = new HashMap<String, String>();
        m.put("test", "test");
        m.put("aa", "aa");
        m.put("callback", "callback");
        m.put("jsonp", "jsonp");
        m.put("cb", "cb");
        JSONP_CALLBACK_ALLOWLIST = Collections.unmodifiableMap(m);
    }

    /**
     * Map a requested JSONP callback name to a server-side constant function name.
     *
     * @return the allowlisted constant name, or null when the request is not allowlisted
     */
    public static String resolveJsonpCallback(String requested) {
        if (requested == null) {
            return null;
        }
        return JSONP_CALLBACK_ALLOWLIST.get(requested);
    }

    /**
     * Build a JSONP response. The function name is a server-side constant chosen
     * through {@link #resolveJsonpCallback(String)}, so request data can never be
     * interpreted as JavaScript.
     */
    public static String json2Jsonp(String callback, String jsonStr) {
        String functionName = resolveJsonpCallback(callback);
        if (functionName == null) {
            return "error";
        }
        // Leading comment mitigates Rosetta-Flash style content sniffing; the JSON
        // payload is additionally made safe for any script/HTML embedding context.
        return "/**/" + functionName + "(" + escapeJsonForScript(jsonStr) + ")";
    }

    /**
     * Escape characters in a JSON document that are dangerous when the document is
     * embedded in JavaScript or HTML. In JSON these characters can only occur inside
     * string literals, so the unicode escapes preserve the decoded value.
     */
    public static String escapeJsonForScript(String jsonStr) {
        if (jsonStr == null) {
            return "null";
        }
        return jsonStr
                .replace("<", "\\u003c")
                .replace(">", "\\u003e")
                .replace("&", "\\u0026")
                .replace("\u2028", "\\u2028")
                .replace("\u2029", "\\u2029");
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
