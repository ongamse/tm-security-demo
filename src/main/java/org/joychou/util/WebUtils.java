package org.joychou.util;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import java.io.*;

import com.google.common.base.Preconditions;
import java.util.regex.Pattern;

public class WebUtils {

    // Request bodies containing XML must be read through org.joychou.security.SecureXml.parse (size capped, DTD rejected).

    public static String getCookieValueByName(HttpServletRequest request, String cookieName) {
        Cookie cookie = org.springframework.web.util.WebUtils.getCookie(request, cookieName);
        return cookie == null ? null : cookie.getValue();
    }


    // JSONP callback must be a plain (dotted) JavaScript identifier, nothing else can reach script context.
    private static final Pattern JSONP_CALLBACK_PATTERN = Pattern.compile("^[A-Za-z_$][A-Za-z0-9_$]{0,63}(\\.[A-Za-z_$][A-Za-z0-9_$]{0,63}){0,3}$");

    public static boolean isValidJsonpCallback(String callback) {
        return callback != null && JSONP_CALLBACK_PATTERN.matcher(callback).matches();
    }

    public static String json2Jsonp(String callback, String jsonStr) {
        if (!isValidJsonpCallback(callback)) {
            return "error";
        }
        return callback + "(" + jsonStr + ")";
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
