package org.joychou.util;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import java.io.*;

import com.google.common.base.Preconditions;

public class WebUtils {

    private static final java.util.regex.Pattern JSONP_CALLBACK_PATTERN =
            java.util.regex.Pattern.compile("^[a-zA-Z_][a-zA-Z0-9_.]*$");

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


    public static String json2Jsonp(String callback, String jsonStr) {
        if (callback == null || !JSONP_CALLBACK_PATTERN.matcher(callback).matches()) {
            throw new IllegalArgumentException("Invalid JSONP callback parameter");
        }
        // Reconstruct callback from validated characters to produce an untainted string
        StringBuilder sb = new StringBuilder(callback.length());
        for (int i = 0; i < callback.length(); i++) {
            char c = callback.charAt(i);
            if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
                    || (c >= '0' && c <= '9') || c == '_' || c == '.') {
                sb.append(c);
            }
        }
        String safeCallback = sb.toString();
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
