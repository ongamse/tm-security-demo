package org.joychou.util;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.*;
import java.nio.charset.StandardCharsets;

import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;

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


    // Fixed set of JSONP callback names the server is willing to emit. The request value is never
    // written to the response; it is only compared against these constants.
    private static final String[] ALLOWED_JSONP_CALLBACKS = {"callback", "jsonp", "cb", "test", "aa"};

    /**
     * Resolve a requested JSONP callback by lookup.
     *
     * @return the server-side constant equal to the requested value, or null when there is no exact match
     */
    public static String matchJsonpCallback(String requested) {
        if (requested == null) {
            return null;
        }
        for (String allowed : ALLOWED_JSONP_CALLBACKS) {
            if (allowed.equals(requested)) {
                return allowed;
            }
        }
        return null;
    }

    private static String escapeLineSeparators(String jsonStr) {
        return jsonStr == null ? "null"
                : jsonStr.replace("\u2028", "\\u2028").replace("\u2029", "\\u2029");
    }

    /**
     * Build a JSONP body using only an allow-listed callback constant (see
     * {@link #matchJsonpCallback(String)}). The body is prefixed with "/**&#47;" (same as Spring's
     * JSONP advice) and line separators in the JSON are escaped so it stays valid JavaScript.
     * When the requested callback is not allow-listed, the plain JSON is returned without a wrapper;
     * use {@link #jsonpResponse(String, String)} to also get the right headers.
     */
    public static String json2Jsonp(String callback, String jsonStr) {
        String matched = matchJsonpCallback(callback);
        String safeJson = escapeLineSeparators(jsonStr);
        if (matched == null) {
            return safeJson;
        }
        return "/**/" + matched + "(" + safeJson + ");";
    }

    /**
     * Set headers and build the body for a JSONP endpoint: script content type for an allow-listed
     * callback, otherwise plain JSON with application/json. Always sends nosniff.
     */
    public static ResponseEntity<String> jsonpResponse(String requestedCallback, String jsonStr) {
        MediaType type = matchJsonpCallback(requestedCallback) == null
                ? new MediaType("application", "json", StandardCharsets.UTF_8)
                : new MediaType("application", "javascript", StandardCharsets.UTF_8);
        return ResponseEntity.ok()
                .contentType(type)
                .header("X-Content-Type-Options", "nosniff")
                .body(json2Jsonp(requestedCallback, jsonStr));
    }


    // Plain text body (no script), never sniffed.
    public static ResponseEntity<String> plainTextResponse(String body) {
        return ResponseEntity.ok()
                .contentType(new MediaType("text", "plain", StandardCharsets.UTF_8))
                .header("X-Content-Type-Options", "nosniff")
                .body(body);
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
