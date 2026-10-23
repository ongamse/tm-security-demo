package org.joychou.controller;

import org.apache.commons.lang.StringUtils;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Set;
import org.springframework.web.util.HtmlUtils;

/**
 * Java get real ip. More details: https://joychou.org/web/how-to-get-real-ip.html
 *
 * @author JoyChou @ 2017-12-29
 */
@RestController
@RequestMapping("/ip")
public class IPForge {

    /**
     * Trusted reverse proxy addresses. X-Real-IP and X-Forwarded-For headers
     * should ONLY be trusted when the direct connection (remoteAddr) comes from
     * a known, trusted reverse proxy. Add your proxy IPs/ranges here.
     */
    private static final Set<String> TRUSTED_PROXY_ADDRS = Set.of(
            "127.0.0.1", "::1"
    );

    // no any proxy
    @RequestMapping("/noproxy")
    public static String noProxy(HttpServletRequest request) {
        return HtmlUtils.htmlEscape(request.getRemoteAddr());
    }


    /**
     * Returns the client IP. When the request arrives through a trusted reverse
     * proxy (whose address is in TRUSTED_PROXY_ADDRS), the X-Real-IP header set
     * by that proxy is used. Otherwise, request.getRemoteAddr() is the canonical
     * source because X-Real-IP / X-Forwarded-For can be freely spoofed by any
     * client when there is no trusted proxy in front of the application.
     */
    @RequestMapping("/proxy")
    @ResponseBody
    public static String proxy(HttpServletRequest request) {
        String remoteAddr = request.getRemoteAddr();

        // Only trust the X-Real-IP header when the immediate caller is a
        // trusted reverse proxy. Without this check, any client can set the
        // header to an arbitrary value, bypassing IP-based access controls.
        if (isTrustedProxy(remoteAddr)) {
            String headerIp = request.getHeader("X-Real-IP");
            if (StringUtils.isNotBlank(headerIp)) {
                return HtmlUtils.htmlEscape(headerIp);
            }
        }

        if (StringUtils.isNotBlank(remoteAddr)) {
            return HtmlUtils.htmlEscape(remoteAddr);
        }
        return "";
    }

    /**
     * Checks whether the given address belongs to a trusted reverse proxy.
     */
    private static boolean isTrustedProxy(String remoteAddr) {
        if (StringUtils.isBlank(remoteAddr)) {
            return false;
        }
        try {
            String normalized = InetAddress.getByName(remoteAddr).getHostAddress();
            return TRUSTED_PROXY_ADDRS.contains(normalized);
        } catch (UnknownHostException e) {
            return false;
        }
    }


}
