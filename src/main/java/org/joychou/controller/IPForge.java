package org.joychou.controller;

import org.apache.commons.lang.StringUtils;
import org.joychou.util.WebUtils;
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

    // Comma separated exact IPs of reverse proxies allowed to set X-Real-IP. Empty (default) trusts none.
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
        // X-Real-IP is client controlled: only honor it when the direct peer is a configured trusted proxy.
        if (isTrustedProxy(remoteAddr)) {
            String ip = request.getHeader("X-Real-IP");
            if (StringUtils.isNotBlank(ip)) {
                return WebUtils.htmlEscape(ip.trim());
            }
        }
        if (StringUtils.isNotBlank(remoteAddr)) {
            return remoteAddr;
        }
        return "";
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
