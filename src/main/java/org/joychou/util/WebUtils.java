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


    private static final com.fasterxml.jackson.databind.ObjectMapper JSONP_MAPPER =
            new com.fasterxml.jackson.databind.ObjectMapper()
                    .configure(com.fasterxml.jackson.core.JsonGenerator.Feature.ESCAPE_NON_ASCII, true);

    /**
     * Wrap an object as JSONP. The callback name is rebuilt from a fixed alphabet by
     * {@link org.joychou.security.SecurityUtil#getSafeJsonpCallback(String)} (constant fallback),
     * so the request string is never copied into the output. The body is produced by Jackson.
     */
    public static String toJsonp(String callback, Object data) {
        String cb = org.joychou.security.SecurityUtil.getSafeJsonpCallback(callback);
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
