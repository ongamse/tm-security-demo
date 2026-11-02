package org.joychou.util;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import java.io.*;
import java.util.regex.Pattern;

import com.google.common.base.Preconditions;

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


    // JSONP callback allowlist: a JavaScript identifier, optionally dotted (e.g. "a.b"), max 64 chars.
    private static final Pattern JSONP_CALLBACK = Pattern.compile("^[A-Za-z_$][A-Za-z0-9_$]*(\\.[A-Za-z_$][A-Za-z0-9_$]*)*$");

    public static boolean isValidJsonpCallback(String callback) {
        return callback != null && callback.length() <= 64 && JSONP_CALLBACK.matcher(callback).matches();
    }

    /**
     * Wrap json in the callback. The callback must be a plain JavaScript identifier,
     * otherwise a constant error body is returned (the callback is never echoed).
     */
    public static String json2Jsonp(String callback, String jsonStr) {
        if (!isValidJsonpCallback(callback)) {
            return "error";
        }
        return callback + "(" + escapeJsonForScript(jsonStr) + ")";
    }

    /**
     * Make serialised JSON safe to embed in executable JavaScript. In valid JSON the characters
     * below can only occur inside string literals, where the \\uXXXX form is equivalent.
     */
    public static String escapeJsonForScript(String json) {
        if (json == null) {
            return "null";
        }
        StringBuilder sb = new StringBuilder(json.length() + 16);
        for (int i = 0; i < json.length(); i++) {
            char c = json.charAt(i);
            if (c == '<' || c == '>' || c == '&' || c == 0x2028 || c == 0x2029) {
                sb.append(String.format("\\u%04x", (int) c));
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    /** Mark a response as JavaScript that browsers must not sniff into another type. */
    public static void setJavascriptHeaders(javax.servlet.http.HttpServletResponse response) {
        response.setContentType("application/javascript;charset=UTF-8");
        response.setHeader("X-Content-Type-Options", "nosniff");
    }


    /**
     * Make an untrusted value safe to write into an HTTP response header (or Location).
     * Strips CR, LF and every other control / line-separator character so the value can
     * never terminate the header line (CRLF / response splitting). Returns null for null.
     */
    public static String sanitizeHeaderValue(String value) {
        if (value == null) {
            return null;
        }
        StringBuilder sb = new StringBuilder(value.length());
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (Character.isISOControl(c) || c == 0x2028 || c == 0x2029) {
                continue;
            }
            sb.append(c);
        }
        return sb.toString();
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
