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


    // JavaScript identifier (optionally dotted) only; anything else is not a valid JSONP callback.
    private static final java.util.regex.Pattern JSONP_CALLBACK_PATTERN =
            java.util.regex.Pattern.compile("^[A-Za-z_$][A-Za-z0-9_$.]{0,63}$");

    // Constant callback used when the requested one is missing or invalid.
    public static final String DEFAULT_JSONP_CALLBACK = "callback";

    private static final com.fasterxml.jackson.databind.ObjectMapper JSONP_MAPPER =
            new com.fasterxml.jackson.databind.ObjectMapper()
                    .configure(com.fasterxml.jackson.core.JsonGenerator.Feature.ESCAPE_NON_ASCII, true);

    public static boolean isSafeJsonpCallback(String callback) {
        return callback != null && JSONP_CALLBACK_PATTERN.matcher(callback).matches();
    }

    /**
     * Wrap an object as JSONP. The callback must pass the strict pattern, otherwise a constant
     * callback name is used. The body is produced by Jackson, never by concatenating request data.
     */
    public static String toJsonp(String callback, Object data) {
        String cb = isSafeJsonpCallback(callback) ? callback : DEFAULT_JSONP_CALLBACK;
        try {
            return "/**/" + cb + "(" + JSONP_MAPPER.writeValueAsString(data) + ")";
        } catch (com.fasterxml.jackson.core.JsonProcessingException e) {
            throw new IllegalStateException("Unable to serialize JSONP body", e);
        }
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
