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

    private static final String JSONP_CALLBACK_ALPHABET =
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_$.";

    /**
     * Re-build a JSONP callback name from a server-side alphabet. Returns null (fail closed)
     * when the callback is not a plain JavaScript identifier path.
     */
    public static String rebuildJsonpCallback(String callback) {
        if (!isSafeJsonpCallback(callback)) {
            return null;
        }
        return rebuildFromAllowed(callback, JSONP_CALLBACK_ALPHABET);
    }

    /**
     * Make serialized JSON safe to embed in a script / JSONP response: the characters that can
     * break out of a script context or terminate a JavaScript string are written as unicode
     * escapes (still valid JSON string escapes).
     */
    public static String escapeJsonForScript(String json) {
        if (json == null) {
            return "null";
        }
        StringBuilder sb = new StringBuilder(json.length() + 16);
        for (int i = 0; i < json.length(); i++) {
            char c = json.charAt(i);
            switch ((int) c) {
                case 0x3c: sb.append("\\u003c"); break;
                case 0x3e: sb.append("\\u003e"); break;
                case 0x26: sb.append("\\u0026"); break;
                case 0x27: sb.append("\\u0027"); break;
                case 0x60: sb.append("\\u0060"); break;
                case 0x2028: sb.append("\\u2028"); break;
                case 0x2029: sb.append("\\u2029"); break;
                default: sb.append(c);
            }
        }
        return sb.toString();
    }

    public static String json2Jsonp(String callback, String jsonStr) {
        String safeCallback = rebuildJsonpCallback(callback);
        if (safeCallback == null) {
            throw new IllegalArgumentException("Illegal jsonp callback");
        }
        return safeCallback + "(" + escapeJsonForScript(jsonStr) + ")";
    }

    /**
     * Contextual HTML encoding for text that is returned to a browser as an HTML body.
     * Escapes the Spring HTML set (& < > " ') plus '/' and backtick.
     */
    public static String htmlEncode(String s) {
        String encoded = HtmlUtils.htmlEscape(s);
        if (encoded == null) {
            return null;
        }
        return encoded.replace("/", "&#x2F;").replace("`", "&#x60;");
    }


    /**
     * Remove CR, LF and all other ISO control characters (except horizontal tab) from a value
     * that is placed into an HTTP response header, to prevent header injection / response splitting.
     * Returns null for null input.
     */
    public static String sanitizeHeaderValue(String value) {
        if (value == null) {
            return null;
        }
        StringBuilder sb = new StringBuilder(value.length());
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c == '\t' || !Character.isISOControl(c)) {
                sb.append(c);
            }
        }
        return sb.toString();
    }


    /**
     * Re-build a value for an HTTP response header from a server-side alphabet. Every output
     * character is taken from {@code allowedChars} (a server constant), never copied from the
     * input. Returns null (fail closed, the caller must not write the header) when the input is
     * null or contains any character that is not in the alphabet, which includes CR, LF and all
     * other control characters.
     */
    public static String rebuildFromAllowed(String value, String allowedChars) {
        if (value == null) {
            return null;
        }
        StringBuilder sb = new StringBuilder(value.length());
        for (int i = 0; i < value.length(); i++) {
            int idx = allowedChars.indexOf(value.charAt(i));
            if (idx < 0) {
                return null;
            }
            sb.append(allowedChars.charAt(idx));
        }
        return sb.toString();
    }


    /**
     * Same as {@link #rebuildFromAllowed(String, String)} but characters outside the alphabet
     * (including CR, LF and other control characters) are replaced by the given server-side
     * constant character instead of rejecting the value. Returns null for null input.
     */
    public static String rebuildFromAllowedOrReplace(String value, String allowedChars, char replacement) {
        if (value == null) {
            return null;
        }
        StringBuilder sb = new StringBuilder(value.length());
        for (int i = 0; i < value.length(); i++) {
            int idx = allowedChars.indexOf(value.charAt(i));
            sb.append(idx < 0 ? replacement : allowedChars.charAt(idx));
        }
        return sb.toString();
    }


    /**
     * Fixed message returned to clients when a request fails. Exception messages, class names and
     * stack traces must never be written into an HTTP response (CWE-209).
     */
    public static final String GENERIC_ERROR = "Request failed.";

    /**
     * Log an exception server-side (sanitized class name and message only) and return the fixed
     * generic error string, which is the only thing that may be sent to the client.
     */
    public static String logAndGenericError(org.slf4j.Logger log, Throwable e) {
        log.error("Request failed: {}: {}", e.getClass().getName(), sanitizeLog(e.getMessage()));
        return GENERIC_ERROR;
    }

    private static final int MAX_LOG_VALUE_LENGTH = 2048;

    /**
     * Neutralize an untrusted value before it is written to a log, to prevent log forging
     * (CWE-117). CR, LF and all other ISO control characters are replaced by an underscore
     * and the value is truncated. Never returns null ("null" is returned for null input).
     */
    public static String sanitizeLog(Object value) {
        if (value == null) {
            return "null";
        }
        String s = String.valueOf(value);
        int len = Math.min(s.length(), MAX_LOG_VALUE_LENGTH);
        StringBuilder sb = new StringBuilder(len + 3);
        for (int i = 0; i < len; i++) {
            char c = s.charAt(i);
            sb.append(Character.isISOControl(c) ? '_' : c);
        }
        if (s.length() > len) {
            sb.append("...");
        }
        return sb.toString();
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
