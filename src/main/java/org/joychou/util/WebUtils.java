package org.joychou.util;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import java.io.*;
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

    /**
     * Wrap json into a JSONP response. The callback is written into JavaScript code,
     * so HTML escaping is not enough: it must match a strict identifier pattern.
     *
     * @throws IllegalArgumentException if the callback is not a valid identifier
     */
    public static String json2Jsonp(String callback, String jsonStr) {
        if (!isValidJsonpCallback(callback)) {
            throw new IllegalArgumentException("Invalid jsonp callback");
        }
        return callback + "(" + jsonStr + ")";
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
