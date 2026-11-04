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


    // A JSONP callback must be a (dotted) JavaScript identifier, nothing else.
    private static final Pattern JSONP_CALLBACK = Pattern.compile("^[A-Za-z_$][A-Za-z0-9_$]{0,63}(\\.[A-Za-z_$][A-Za-z0-9_$]{0,63}){0,3}$");

    public static boolean isValidJsonpCallback(String callback) {
        return callback != null && JSONP_CALLBACK.matcher(callback).matches();
    }

    /**
     * Make a JSON document safe to embed in a script context: characters that can terminate a
     * script block or a JavaScript string literal are replaced with \\uXXXX escapes. These
     * characters can only occur inside JSON string literals, where the escapes are equivalent.
     */
    public static String escapeJsonForScript(String jsonStr) {
        if (jsonStr == null) {
            return "null";
        }
        StringBuilder sb = new StringBuilder(jsonStr.length() + 16);
        for (int i = 0; i < jsonStr.length(); i++) {
            char c = jsonStr.charAt(i);
            switch (c) {
                case '<':
                case '>':
                case '&':
                case '\'':
                case 0x2028:
                case 0x2029:
                    sb.append(String.format("\\u%04x", (int) c));
                    break;
                default:
                    sb.append(c);
            }
        }
        return sb.toString();
    }

    public static String json2Jsonp(String callback, String jsonStr) {
        if (!isValidJsonpCallback(callback)) {
            return "error";
        }
        // The "/**/" prefix prevents the response from being sniffed as another content type.
        return "/**/" + callback + "(" + escapeJsonForScript(jsonStr) + ")";
    }


    /**
     * Check that a request-derived value is safe to write into an HTTP response header.
     * Rejects CR, LF and other control characters (tab is allowed) to prevent header injection / response splitting.
     * A null value is considered safe.
     */
    public static boolean isSafeHeaderValue(String value) {
        if (value == null) {
            return true;
        }
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if ((c < 0x20 && c != '\t') || c == 0x7f) {
                return false;
            }
        }
        return true;
    }


    private static final int MAX_HEADER_VALUE_LENGTH = 2048;

    private static final Pattern COOKIE_VALUE = Pattern.compile("^[A-Za-z0-9_-]{1,256}$");

    /**
     * Strict check for a value that is about to be written to a response header.
     * Rejects (never sanitises) null/empty values, values longer than 2048 chars and any char outside
     * printable ASCII (0x20-0x7e), which excludes CR, LF, other control chars, DEL and non-ASCII.
     */
    public static boolean isStrictHeaderValue(String value) {
        if (value == null || value.isEmpty() || value.length() > MAX_HEADER_VALUE_LENGTH) {
            return false;
        }
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c < 0x20 || c > 0x7e) {
                return false;
            }
        }
        return true;
    }

    /**
     * Strict check for a cookie value: URL-safe base64 style characters only, 1-256 chars.
     */
    public static boolean isStrictCookieValue(String value) {
        return value != null && COOKIE_VALUE.matcher(value).matches();
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
