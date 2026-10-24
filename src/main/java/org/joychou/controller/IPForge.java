package org.joychou.controller;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import java.util.regex.Pattern;

/**
 * Java get real ip. More details: https://joychou.org/web/how-to-get-real-ip.html
 *
 * @author JoyChou @ 2017-12-29
 */
@RestController
@RequestMapping("/ip")
public class IPForge {

    private static final Pattern IP_PATTERN = Pattern.compile(
            "^(?:(?:25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\.){3}(?:25[0-5]|2[0-4]\\d|[01]?\\d\\d?)$"
            + "|^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$"
            + "|^::1$"
    );

    @RequestMapping("/noproxy")
    public static String noProxy(HttpServletRequest request) {
        return request.getRemoteAddr();
    }

    /**
     * When behind a trusted reverse proxy, retrieve the client IP from the
     * rightmost entry in X-Forwarded-For (the value appended by the proxy
     * itself). Fall back to getRemoteAddr() when the header is absent,
     * empty, or contains a value that does not look like a valid IP.
     */
    @RequestMapping("/proxy")
    @ResponseBody
    public static String proxy(HttpServletRequest request) {
        String remoteAddr = request.getRemoteAddr();

        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.trim().isEmpty()) {
            String[] parts = xForwardedFor.split(",");
            String lastEntry = parts[parts.length - 1].trim();
            if (isValidIp(lastEntry)) {
                return lastEntry;
            }
        }

        return (remoteAddr != null) ? remoteAddr : "";
    }

    private static boolean isValidIp(String ip) {
        return ip != null && !ip.isEmpty() && IP_PATTERN.matcher(ip).matches();
    }

}
