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


    private static final java.util.regex.Pattern JSONP_CALLBACK =
            java.util.regex.Pattern.compile("^[A-Za-z_$][A-Za-z0-9_$.]{0,63}$");

    // Strict JavaScript identifier allowlist for JSONP callback names.
    public static boolean isValidJsonpCallback(String callback) {
        return callback != null && JSONP_CALLBACK.matcher(callback).matches();
    }

    /**
     * Rebuild a validated callback name character by character, appending only
     * characters from [A-Za-z0-9_$.]. The returned string is a new value that never
     * contains anything outside the identifier allowlist. Throws if the callback is invalid.
     */
    public static String rebuildJsonpCallback(String callback) {
        if (!isValidJsonpCallback(callback)) {
            throw new IllegalArgumentException("invalid jsonp callback");
        }
        StringBuilder sb = new StringBuilder(callback.length());
        for (int i = 0; i < callback.length(); i++) {
            char c = callback.charAt(i);
            if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
                    || c == '_' || c == '$' || c == '.') {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    /**
     * Escape JSON text for embedding in a script/HTML context. Characters that could
     * break out of the context (&lt;, &gt;, &amp;, quote-less control chars, U+2028/9,
     * and any non-ASCII-printable char) are emitted as \\uXXXX escapes, which are
     * valid inside JSON strings.
     */
    public static String escapeJsonForScript(String jsonStr) {
        if (jsonStr == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder(jsonStr.length() + 16);
        for (int i = 0; i < jsonStr.length(); i++) {
            char c = jsonStr.charAt(i);
            if (c == '<' || c == '>' || c == '&' || c == '\'' || c < 0x20 || c > 0x7e) {
                sb.append(String.format("\\u%04x", (int) c));
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    /**
     * Build a JSONP body. The callback must match a strict identifier regex and is
     * rebuilt character by character, otherwise IllegalArgumentException is thrown.
     * The "/**&#47;" prefix prevents Rosetta Flash style content sniffing.
     */
    public static String json2Jsonp(String callback, String jsonStr) {
        String safeCallback = rebuildJsonpCallback(callback);
        return "/**/" + safeCallback + "(" + escapeJsonForScript(jsonStr) + ")";
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
