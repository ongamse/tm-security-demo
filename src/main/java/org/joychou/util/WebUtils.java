package org.joychou.util;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import java.io.*;

import com.google.common.base.Preconditions;
import org.springframework.web.util.HtmlUtils;

public class WebUtils {

    // Get request body.
    // Upper bound for a request body that is later handed to a parser (guards against entity/size blow-ups).
    private static final int MAX_REQUEST_BODY_BYTES = 1024 * 1024;

    public static String getRequestBody(HttpServletRequest request) throws IOException {
        try (InputStream in = request.getInputStream()) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buf = new byte[4096];
            int total = 0;
            int n;
            while ((n = in.read(buf)) != -1) {
                total += n;
                if (total > MAX_REQUEST_BODY_BYTES) {
                    throw new IOException("Request body exceeds " + MAX_REQUEST_BODY_BYTES + " bytes");
                }
                out.write(buf, 0, n);
            }
            return new String(out.toByteArray(), java.nio.charset.Charset.defaultCharset());
        }
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


    // A JSONP callback must be a plain JavaScript identifier path such as "cb" or "window.cb_1".
    private static final java.util.regex.Pattern JSONP_CALLBACK_PATTERN =
            java.util.regex.Pattern.compile("^[a-zA-Z_$][a-zA-Z0-9_$]*(\\.[a-zA-Z_$][a-zA-Z0-9_$]*)*$");

    public static boolean isValidJsonpCallback(String callback) {
        return callback != null && callback.length() <= 128 && JSONP_CALLBACK_PATTERN.matcher(callback).matches();
    }

    public static String json2Jsonp(String callback, String jsonStr) {
        if (!isValidJsonpCallback(callback)) {
            return "error";
        }
        return callback + "(" + jsonStr + ")";
    }

    // Contextual HTML encoding for values reflected in a text/html response body.
    public static String htmlEscape(String value) {
        return value == null ? null : HtmlUtils.htmlEscape(value);
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
