package org.joychou.util;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import java.io.*;

import com.google.common.base.Preconditions;

import java.util.regex.Pattern;

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
    private static final Pattern JSONP_CALLBACK_PATTERN = Pattern.compile("^[A-Za-z_$][A-Za-z0-9_$.]{0,63}$");

    public static boolean isValidJsonpCallback(String callback) {
        return callback != null && JSONP_CALLBACK_PATTERN.matcher(callback).matches();
    }

    // Constant alphabet used to rebuild callback names; emitted characters always come from here.
    private static final String JSONP_CALLBACK_ALPHABET =
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_$.";

    /**
     * Returns a callback name rebuilt character by character from a server-side constant
     * alphabet, or null when the request value is not a plain JavaScript identifier path.
     * No character of the request string is copied into the returned value. Callers must use
     * only the returned value, never the raw request parameter.
     */
    public static String validatedJsonpCallback(String callback) {
        if (!isValidJsonpCallback(callback)) {
            return null;
        }
        StringBuilder rebuilt = new StringBuilder(callback.length());
        for (int i = 0; i < callback.length(); i++) {
            int idx = JSONP_CALLBACK_ALPHABET.indexOf(callback.charAt(i));
            if (idx < 0) {
                return null;
            }
            rebuilt.append(JSONP_CALLBACK_ALPHABET.charAt(idx));
        }
        return rebuilt.toString();
    }

    public static String json2Jsonp(String callback, String jsonStr) {
        String safeCallback = validatedJsonpCallback(callback);
        if (safeCallback == null) {
            return "error";
        }
        return safeCallback + "(" + jsonStr + ")";
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
