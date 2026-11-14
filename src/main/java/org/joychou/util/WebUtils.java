package org.joychou.util;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
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


    // JSONP callback must be a plain JavaScript identifier path such as "foo" or "ns.foo_1".
    private static final Pattern JSONP_CALLBACK = Pattern.compile("^[A-Za-z_$][A-Za-z0-9_$]*(\\.[A-Za-z_$][A-Za-z0-9_$]*)*$");

    public static boolean isValidJsonpCallback(String callback) {
        return callback != null && callback.length() <= 128 && JSONP_CALLBACK.matcher(callback).matches();
    }

    /**
     * Build a JSONP body. The callback is only used after a strict identifier-path match, the
     * body is prefixed with "/**&#47;" (same as Spring's JSONP advice) to defeat Rosetta-Flash style
     * abuse, and the JSON payload has line separators escaped so it stays valid JavaScript.
     * Callers must also send {@link #setJsonpHeaders(HttpServletResponse)}.
     */
    public static String json2Jsonp(String callback, String jsonStr) {
        if (!isValidJsonpCallback(callback)) {
            return "error";
        }
        String safeJson = jsonStr == null ? "null"
                : jsonStr.replace("\u2028", "\\u2028").replace("\u2029", "\\u2029");
        return "/**/" + callback + "(" + safeJson + ");";
    }

    // Force the JSONP response to be treated as script only, never sniffed as HTML.
    public static void setJsonpHeaders(HttpServletResponse response) {
        response.setContentType("application/javascript;charset=UTF-8");
        response.setHeader("X-Content-Type-Options", "nosniff");
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
