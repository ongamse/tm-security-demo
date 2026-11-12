package org.joychou.controller;

import org.apache.commons.lang.StringUtils;
import org.joychou.security.SecurityUtil;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.util.HtmlUtils;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import java.util.HashSet;
import java.util.Set;

/**
 * Java get real ip. More details: https://joychou.org/web/how-to-get-real-ip.html
 *
 * @author JoyChou @ 2017-12-29
 */
@RestController
@RequestMapping("/ip")
public class IPForge {

    /**
     * Comma separated list of literal reverse proxy addresses whose X-Forwarded-For header is trusted.
     * Empty (default) means the header is never trusted.
     */
    @Value("${joychou.security.trusted.proxies:}")
    private String trustedProxies;

    // no any proxy
    @RequestMapping(value = "/noproxy", produces = "text/plain;charset=UTF-8")
    public String noProxy(HttpServletRequest request) {
        // Canonical text rebuilt from the parsed address bytes, then HTML escaped.
        String ip = SecurityUtil.normalizeIpLiteral(request.getRemoteAddr());
        return HtmlUtils.htmlEscape(ip == null ? "unknown" : ip);
    }


    /**
     * proxy_set_header X-Real-IP $remote_addr;
     * proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for
     * if code used X-Forwarded-For to get ip, the code must be vulnerable.
     */
    @RequestMapping("/proxy")
    @ResponseBody
    public String proxy(HttpServletRequest request) {
        // The client ip is the TCP peer address unless the peer is a configured trusted proxy;
        // then the right-most untrusted, literal-ip hop of X-Forwarded-For is used.
        String ip = SecurityUtil.resolveClientIp(request, trustedProxySet());
        return HtmlUtils.htmlEscape(ip);
    }

    private Set<String> trustedProxySet() {
        Set<String> proxies = new HashSet<String>();
        if (StringUtils.isBlank(trustedProxies)) {
            return proxies;
        }
        for (String proxyAddr : trustedProxies.split(",")) {
            String normalized = SecurityUtil.normalizeIpLiteral(proxyAddr.trim());
            if (normalized != null) {
                proxies.add(normalized);
            }
        }
        return proxies;
    }


}
