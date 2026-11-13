package org.joychou.controller;

import org.apache.commons.lang.StringUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.HtmlUtils;

import javax.servlet.http.HttpServletRequest;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.regex.Pattern;

/**
 * Java get real ip. More details: https://joychou.org/web/how-to-get-real-ip.html
 *
 * @author JoyChou @ 2017-12-29
 */
@RestController
@RequestMapping("/ip")
public class IPForge {

    // Comma-separated list of reverse proxy IPs allowed to set X-Real-IP. Empty = trust none.
    @Value("${joychou.security.trusted.proxies:}")
    private String trustedProxies;

    // no any proxy
    @RequestMapping("/noproxy")
    public static String noProxy(HttpServletRequest request) {
        return request.getRemoteAddr();
    }


    /**
     * proxy_set_header X-Real-IP $remote_addr;
     * proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for
     * if code used X-Forwarded-For to get ip, the code must be vulnerable.
     */
    @RequestMapping("/proxy")
    @ResponseBody
    public String proxy(HttpServletRequest request) {
        String remoteAddr = request.getRemoteAddr();
        // Only trust X-Real-IP when the immediate peer is a configured trusted proxy.
        if (isTrustedProxy(remoteAddr)) {
            // Header value is only accepted if it is a literal IP address (no DNS lookup).
            String ip = parseLiteralIp(request.getHeader("X-Real-IP"));
            if (ip != null) {
                return HtmlUtils.htmlEscape(ip);
            }
        }
        if (StringUtils.isNotBlank(remoteAddr)) {
            return HtmlUtils.htmlEscape(remoteAddr);
        }
        return "";
    }

    private static final Pattern IPV4 = Pattern.compile(
            "^((25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)\\.){3}(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)$");
    private static final Pattern IPV6_CHARS = Pattern.compile("^[0-9a-fA-F:.]{2,45}$");

    /**
     * Returns the normalized literal IPv4/IPv6 address, or null if the value is not one.
     * The IPv6 branch is only reached for hex/colon/dot strings containing ':', which
     * InetAddress parses as a literal without any DNS resolution.
     */
    private static String parseLiteralIp(String value) {
        if (value == null) {
            return null;
        }
        String v = value.trim();
        if (IPV4.matcher(v).matches()) {
            return v;
        }
        if (v.indexOf(':') >= 0 && IPV6_CHARS.matcher(v).matches()) {
            try {
                return InetAddress.getByName(v).getHostAddress();
            } catch (UnknownHostException e) {
                return null;
            }
        }
        return null;
    }

    private boolean isTrustedProxy(String remoteAddr) {
        if (StringUtils.isBlank(remoteAddr) || StringUtils.isBlank(trustedProxies)) {
            return false;
        }
        for (String proxy : trustedProxies.split(",")) {
            if (remoteAddr.equals(proxy.trim())) {
                return true;
            }
        }
        return false;
    }


}
