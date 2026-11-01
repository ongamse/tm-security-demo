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

    // Only hex digits, dots and colons, so InetAddress.getByName can never trigger a DNS lookup.
    private static final Pattern IP_LITERAL = Pattern.compile("^(?=.*[.:])[0-9A-Fa-f:.]{2,45}$");

    // Comma-separated list of trusted reverse proxy IPs; empty means no proxy is trusted.
    @Value("${joychou.security.trusted.proxies:}")
    private String trustedProxies;

    // no any proxy
    @RequestMapping("/noproxy")
    public static String noProxy(HttpServletRequest request) {
        // The address is intentionally not reflected into the response body.
        return "ok";
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
        String ip = "";
        // Only honor the forwarding header when the direct peer is a trusted proxy.
        if (isTrustedProxy(remoteAddr)) {
            String header = request.getHeader("X-Real-IP");
            if (StringUtils.isNotBlank(header)) {
                InetAddress forwarded = parseIpLiteral(header.trim());
                if (forwarded != null) {
                    ip = forwarded.getHostAddress();
                }
            }
        }
        if (StringUtils.isBlank(ip) && StringUtils.isNotBlank(remoteAddr)) {
            ip = remoteAddr;
        }
        return HtmlUtils.htmlEscape(ip);
    }

    private boolean isTrustedProxy(String remoteAddr) {
        InetAddress peer = parseIpLiteral(remoteAddr);
        if (peer == null || StringUtils.isBlank(trustedProxies)) {
            return false;
        }
        for (String candidate : trustedProxies.split(",")) {
            InetAddress trusted = parseIpLiteral(candidate.trim());
            if (trusted != null && trusted.equals(peer)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Parse a literal IPv4/IPv6 address. Returns null for anything else; never performs a DNS lookup.
     */
    private static InetAddress parseIpLiteral(String value) {
        if (value == null || !IP_LITERAL.matcher(value).matches()) {
            return null;
        }
        try {
            return InetAddress.getByName(value);
        } catch (UnknownHostException e) {
            return null;
        }
    }


}
