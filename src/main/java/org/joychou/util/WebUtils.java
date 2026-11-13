package org.joychou.util;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import java.io.*;

import com.google.common.base.Preconditions;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;
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


    // Strict JavaScript identifier (optionally dotted) allowlist for JSONP callback names.
    private static final Pattern JSONP_CALLBACK = Pattern.compile("^[A-Za-z_$][A-Za-z0-9_$.]{0,63}$");

    /**
     * @return true only if the callback is a safe JavaScript identifier / dotted path.
     */
    public static boolean isValidJsonpCallback(String callback) {
        return callback != null && JSONP_CALLBACK.matcher(callback).matches();
    }

    // Server-owned JSONP callback names (those used by this demo's docs and templates).
    private static final Set<String> ALLOWED_JSONP_CALLBACKS = Collections.unmodifiableSet(
            new LinkedHashSet<String>(Arrays.asList(
                    "callback", "_callback", "jsonp", "cb", "handleResponse", "jQuery", "test", "aa")));

    /**
     * Resolve a request-supplied callback to the allowlist's own string. The request value is
     * only used for lookup and is never written out.
     *
     * @return the allowlisted callback name, or null when the value is invalid or not allowlisted.
     */
    public static String resolveJsonpCallback(String callback) {
        if (!isValidJsonpCallback(callback)) {
            return null;
        }
        for (String allowed : ALLOWED_JSONP_CALLBACKS) {
            if (allowed.equals(callback)) {
                return allowed;
            }
        }
        return null;
    }

    /**
     * Wrap json with a server-owned callback name. An invalid, unknown or missing callback is
     * never reflected: the plain JSON is returned instead.
     */
    public static String json2Jsonp(String callback, String jsonStr) {
        String safeCallback = resolveJsonpCallback(callback);
        if (safeCallback == null) {
            return jsonStr;
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
