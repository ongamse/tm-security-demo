package org.joychou.util;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import java.io.*;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

import com.google.common.base.Preconditions;

public class WebUtils {

    // Get request body.
    public static String getRequestBody(HttpServletRequest request) throws IOException {
        InputStream in = request.getInputStream();
        return convertStreamToString(in);
    }

    /**
     * Read the request body once with a hard size cap. UTF-16 bodies with a byte order mark are
     * decoded as UTF-16; otherwise the request charset is used (UTF-8 when absent or unknown).
     *
     * @return the decoded body, or null when the body is larger than maxBytes
     */
    public static String getRequestBody(HttpServletRequest request, int maxBytes) throws IOException {
        InputStream in = request.getInputStream();
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        byte[] buf = new byte[4096];
        int total = 0;
        int n;
        while ((n = in.read(buf)) != -1) {
            total += n;
            if (total > maxBytes) {
                return null;
            }
            bos.write(buf, 0, n);
        }
        byte[] data = bos.toByteArray();

        Charset cs = StandardCharsets.UTF_8;
        if (data.length >= 2 && ((data[0] == (byte) 0xFE && data[1] == (byte) 0xFF)
                || (data[0] == (byte) 0xFF && data[1] == (byte) 0xFE))) {
            cs = StandardCharsets.UTF_16;
        } else if (request.getCharacterEncoding() != null) {
            try {
                cs = Charset.forName(request.getCharacterEncoding());
            } catch (IllegalArgumentException e) {
                cs = StandardCharsets.UTF_8;
            }
        }
        return new String(data, cs);
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


    private static final java.util.regex.Pattern JS_CALLBACK =
            java.util.regex.Pattern.compile("^[A-Za-z_$][A-Za-z0-9_$.]{0,127}$");

    /**
     * Only plain JavaScript identifiers (optionally dotted) are valid JSONP callback names.
     */
    public static boolean isValidJsCallback(String callback) {
        return callback != null && JS_CALLBACK.matcher(callback).matches();
    }

    /**
     * Make serialized JSON safe to embed in a script/HTML response. The characters are replaced by
     * JSON unicode escapes, so the result is still valid JSON/JavaScript with identical meaning.
     */
    public static String escapeJsonForScript(String jsonStr) {
        if (jsonStr == null) {
            return null;
        }
        return jsonStr.replace("<", "\\u003c")
                .replace(">", "\\u003e")
                .replace("&", "\\u0026")
                .replace(String.valueOf((char) 0x2028), "\\u2028")
                .replace(String.valueOf((char) 0x2029), "\\u2029");
    }

    public static String json2Jsonp(String callback, String jsonStr) {
        String safeJson = escapeJsonForScript(jsonStr);
        if (!isValidJsCallback(callback)) {
            // No usable callback name: return the plain JSON instead of reflecting the parameter.
            return safeJson;
        }
        return callback + "(" + safeJson + ")";
    }


    private static final java.util.regex.Pattern HEADER_CONTROL_CHARS =
            java.util.regex.Pattern.compile("[\\p{Cntrl}\\u0085\\u2028\\u2029]");

    /**
     * Remove CR, LF and all other control characters from a value that is written into an HTTP
     * response header, so that attacker-controlled data cannot split the response (CWE-113).
     * Returns null for null input.
     */
    public static String sanitizeHeaderValue(String value) {
        if (value == null) {
            return null;
        }
        return HEADER_CONTROL_CHARS.matcher(value).replaceAll("");
    }


    private static final java.util.regex.Pattern SAFE_HEADER_VALUE =
            java.util.regex.Pattern.compile("[\\w .:/@=,;*+\\-]{0,200}");

    private static final java.util.regex.Pattern SAFE_URL_HEADER_VALUE =
            java.util.regex.Pattern.compile("[A-Za-z0-9\\-._~:/?#\\[\\]@!$&'()*+,;=%]{1,2048}");

    /**
     * Strict allowlist check for a value that is written into an HTTP response header (CWE-113).
     * null and the empty string are accepted; anything containing CR, LF, other control characters
     * or characters outside the allowlist is rejected. Callers must reject the request (HTTP 400)
     * instead of writing the header when this returns false.
     */
    public static boolean isSafeHeaderValue(String value) {
        return value == null || SAFE_HEADER_VALUE.matcher(value).matches();
    }

    /**
     * Same as {@link #isSafeHeaderValue(String)} but for absolute/relative URLs written into a
     * Location header: only RFC 3986 URL characters are accepted (no whitespace, no control
     * characters, no non-ASCII), the value must not be empty.
     */
    public static boolean isSafeUrlHeaderValue(String url) {
        return url != null && SAFE_URL_HEADER_VALUE.matcher(url).matches();
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
