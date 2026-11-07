package org.joychou.controller;

import org.apache.commons.lang.StringUtils;
import org.springframework.web.util.HtmlUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;

/**
 * Java get real ip. More details: https://joychou.org/web/how-to-get-real-ip.html
 *
 * @author JoyChou @ 2017-12-29
 */
@RestController
@RequestMapping("/ip")
public class IPForge {

    // Comma separated exact IPs of reverse proxies whose X-Forwarded-For is honored. Empty (default) trusts none.
    @Value("${joychou.security.trusted.proxies:}")
    private String trustedProxies;

    // no any proxy
    @RequestMapping("/noproxy")
    public static String noProxy(HttpServletRequest request) {
        return HtmlUtils.htmlEscape(request.getRemoteAddr());
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
        // Forwarded headers are client controlled: only consult them when the direct peer is a configured
        // trusted proxy. Otherwise the socket peer address is the only trustworthy value.
        if (isTrustedProxy(remoteAddr)) {
            String forwarded = clientIpFromForwardedFor(request.getHeader("X-Forwarded-For"));
            if (forwarded != null) {
                return HtmlUtils.htmlEscape(forwarded);
            }
        }
        if (StringUtils.isNotBlank(remoteAddr)) {
            return HtmlUtils.htmlEscape(remoteAddr);
        }
        return "";
    }

    /**
     * Walk X-Forwarded-For from the right (the entries appended by our own proxies) and return the first
     * entry that is not a trusted proxy. Left-most entries are client supplied and are never used. Returns
     * null when the header is absent or the selected entry is not a literal IPv4/IPv6 address.
     */
    private String clientIpFromForwardedFor(String header) {
        if (StringUtils.isBlank(header)) {
            return null;
        }
        String[] parts = header.split(",");
        for (int i = parts.length - 1; i >= 0; i--) {
            String candidate = parts[i].trim();
            if (isTrustedProxy(candidate)) {
                continue;
            }
            return isLiteralIp(candidate) ? candidate : null;
        }
        return null;
    }

    private static boolean isLiteralIp(String value) {
        return value != null && (IPV4.matcher(value).matches() || IPV6.matcher(value).matches());
    }

    private static final java.util.regex.Pattern IPV4 = java.util.regex.Pattern.compile(
            "^((25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)\\.){3}(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)$");

    private static final java.util.regex.Pattern IPV6 = java.util.regex.Pattern.compile(
            "^(([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}"
            + "|([0-9a-fA-F]{1,4}:){1,7}:"
            + "|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}"
            + "|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}"
            + "|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}"
            + "|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}"
            + "|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}"
            + "|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})"
            + "|:((:[0-9a-fA-F]{1,4}){1,7}|:))$");

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
