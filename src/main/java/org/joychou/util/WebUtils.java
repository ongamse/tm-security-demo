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


    // A JSONP callback must be a plain JavaScript identifier path such as "cb" or "window.cb".
    private static final Pattern JSONP_CALLBACK = Pattern.compile("^[A-Za-z_$][A-Za-z0-9_$]*(\\.[A-Za-z_$][A-Za-z0-9_$]*)*$");

    public static boolean isSafeJsonpCallback(String callback) {
        return callback != null && callback.length() <= 128 && JSONP_CALLBACK.matcher(callback).matches();
    }

    public static String json2Jsonp(String callback, String jsonStr) {
        if (!isSafeJsonpCallback(callback)) {
            throw new IllegalArgumentException("Illegal jsonp callback");
        }
        return callback + "(" + jsonStr + ")";
    }

    /**
     * Contextual HTML encoding for text that is returned to a browser as an HTML body.
     */
    public static String htmlEncode(String s) {
        return HtmlUtils.htmlEscape(s);
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
