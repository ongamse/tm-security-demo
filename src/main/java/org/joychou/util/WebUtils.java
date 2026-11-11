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


    private static final java.util.regex.Pattern JSONP_CALLBACK = java.util.regex.Pattern.compile("^[A-Za-z_$][A-Za-z0-9_$.]{0,63}$");

    // Only a plain JS identifier / dotted path is accepted as the JSONP callback name.
    public static boolean isValidJsonpCallback(String callback) {
        return callback != null && JSONP_CALLBACK.matcher(callback).matches();
    }

    // Escape HTML-significant characters inside JSON string values (< is valid JSON).
    public static String escapeJsonForHtml(String jsonStr) {
        return jsonStr.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026");
    }

    private static final String CALLBACK_ALPHABET =
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_$.";

    private static final String JSON_ALPHABET =
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 {}[]\":,._-@()\\=+*!?%#";

    private static final String TEXT_ALPHABET =
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 .,:_-@()[]=";

    private static final String DIGITS = "0123456789";

    private static final String HEX = "0123456789abcdef";

    // Rebuild a callback name char by char from a constant alphabet (nothing else is ever emitted).
    private static String rebuildCallback(String callback) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < callback.length(); i++) {
            int idx = CALLBACK_ALPHABET.indexOf(callback.charAt(i));
            if (idx >= 0) {
                sb.append(CALLBACK_ALPHABET.charAt(idx));
            }
        }
        return sb.toString();
    }

    // Rebuild JSON text from a constant alphabet; every other char becomes a JSON unicode escape
    // whose hex digits also come from a constant alphabet.
    private static String rebuildJson(String jsonStr) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < jsonStr.length(); i++) {
            char c = jsonStr.charAt(i);
            int idx = JSON_ALPHABET.indexOf(c);
            if (idx >= 0) {
                sb.append(JSON_ALPHABET.charAt(idx));
            } else {
                sb.append("\\u");
                for (int shift = 12; shift >= 0; shift -= 4) {
                    sb.append(HEX.charAt((c >> shift) & 0xF));
                }
            }
        }
        return sb.toString();
    }

    /**
     * Rebuild text for an HTML response from a constant alphabet; every other code point is
     * emitted as a numeric character reference with digits taken from a constant alphabet.
     */
    public static String htmlSafeRebuild(String text) {
        StringBuilder sb = new StringBuilder();
        if (text == null) {
            return sb.toString();
        }
        int i = 0;
        while (i < text.length()) {
            int cp = text.codePointAt(i);
            i += Character.charCount(cp);
            int idx = cp < 128 ? TEXT_ALPHABET.indexOf((char) cp) : -1;
            if (idx >= 0) {
                sb.append(TEXT_ALPHABET.charAt(idx));
            } else {
                sb.append("&#");
                String dec = Integer.toString(cp);
                for (int j = 0; j < dec.length(); j++) {
                    sb.append(DIGITS.charAt(dec.charAt(j) - '0'));
                }
                sb.append(';');
            }
        }
        return sb.toString();
    }

    public static String json2Jsonp(String callback, String jsonStr) {
        if (!isValidJsonpCallback(callback)) {
            return "error";
        }
        return rebuildCallback(callback) + "(" + rebuildJson(jsonStr) + ")";
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
