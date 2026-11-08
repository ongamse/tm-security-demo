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


    /** Constant table of characters permitted in a JSONP callback name. */
    private static final String CALLBACK_FIRST_CHARS =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_$";
    private static final String CALLBACK_REST_CHARS = CALLBACK_FIRST_CHARS + "0123456789.";
    private static final int CALLBACK_MAX_LEN = 64;
    public static final String DEFAULT_CALLBACK = "callback";

    /**
     * Returns a JavaScript-safe JSONP callback name. The name must match
     * ^[A-Za-z_$][A-Za-z0-9_$.]{0,63}$ and is rebuilt character by character from a constant
     * table; any mismatch yields the constant default callback name.
     */
    public static String safeCallback(String callback) {
        if (callback == null || callback.isEmpty() || callback.length() > CALLBACK_MAX_LEN) {
            return DEFAULT_CALLBACK;
        }
        StringBuilder sb = new StringBuilder(callback.length());
        for (int i = 0; i < callback.length(); i++) {
            String table = (i == 0) ? CALLBACK_FIRST_CHARS : CALLBACK_REST_CHARS;
            int idx = table.indexOf(callback.charAt(i));
            if (idx < 0) {
                return DEFAULT_CALLBACK;
            }
            sb.append(table.charAt(idx));
        }
        return sb.toString();
    }

    public static String json2Jsonp(String callback, String jsonStr) {
        return safeCallback(callback) + "(" + jsonStr + ")";
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
