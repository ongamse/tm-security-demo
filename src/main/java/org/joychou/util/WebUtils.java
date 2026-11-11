package org.joychou.util;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import java.io.*;

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


    private static final java.util.regex.Pattern JSONP_CALLBACK = java.util.regex.Pattern.compile("^[A-Za-z_$][A-Za-z0-9_$.]{0,63}$");

    // Only a plain JS identifier / dotted path is accepted as the JSONP callback name.
    public static boolean isValidJsonpCallback(String callback) {
        return callback != null && JSONP_CALLBACK.matcher(callback).matches();
    }

    // Escape HTML-significant characters inside JSON string values (< is valid JSON).
    public static String escapeJsonForHtml(String jsonStr) {
        return jsonStr.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026");
    }

    public static String json2Jsonp(String callback, String jsonStr) {
        if (!isValidJsonpCallback(callback)) {
            return "error";
        }
        return HtmlUtils.htmlEscape(callback) + "(" + escapeJsonForHtml(jsonStr) + ")";
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
