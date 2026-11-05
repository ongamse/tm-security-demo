package org.joychou.util;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import java.io.*;

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


    private static final java.util.regex.Pattern JS_CALLBACK =
            java.util.regex.Pattern.compile("^[A-Za-z_$][A-Za-z0-9_$.]{0,127}$");

    /**
     * Only plain JavaScript identifiers (optionally dotted) are valid JSONP callback names.
     */
    public static boolean isValidJsCallback(String callback) {
        return callback != null && JS_CALLBACK.matcher(callback).matches();
    }

    /**
     * Make serialized JSON safe to embed in a script/HTML response. The characters are replaced by
     * JSON unicode escapes, so the result is still valid JSON/JavaScript with identical meaning.
     */
    public static String escapeJsonForScript(String jsonStr) {
        if (jsonStr == null) {
            return null;
        }
        return jsonStr.replace("<", "\\u003c")
                .replace(">", "\\u003e")
                .replace("&", "\\u0026")
                .replace(String.valueOf((char) 0x2028), "\\u2028")
                .replace(String.valueOf((char) 0x2029), "\\u2029");
    }

    public static String json2Jsonp(String callback, String jsonStr) {
        String safeJson = escapeJsonForScript(jsonStr);
        if (!isValidJsCallback(callback)) {
            // No usable callback name: return the plain JSON instead of reflecting the parameter.
            return safeJson;
        }
        return callback + "(" + safeJson + ")";
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
