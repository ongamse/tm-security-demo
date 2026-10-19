package org.joychou.controller;

import org.apache.commons.lang.StringUtils;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.HtmlUtils;

import javax.servlet.http.HttpServletRequest;

/**
 * Java get real ip. More details: https://joychou.org/web/how-to-get-real-ip.html
 *
 * @author JoyChou @ 2017-12-29
 */
@RestController
@RequestMapping("/ip")
public class IPForge {

    // no any proxy
    @RequestMapping("/noproxy")
    public static String noProxy(HttpServletRequest request) {
        return HtmlUtils.htmlEscape(request.getRemoteAddr());
    }


    /**
     * Use request.getRemoteAddr() as the authoritative client IP source.
     * X-Real-IP / X-Forwarded-For headers are client-controlled and must only
     * be trusted when the immediate peer (remoteAddr) is a known reverse proxy.
     * In production, configure TRUSTED_PROXIES with actual proxy addresses.
     */
    // Production: populate with real proxy IPs, e.g. {"10.0.0.1", "10.0.0.2"}
    private static final java.util.Set<String> TRUSTED_PROXIES = java.util.Collections.emptySet();

    @RequestMapping("/proxy")
    @ResponseBody
    public static String proxy(HttpServletRequest request) {
        String remoteAddr = request.getRemoteAddr();
        // Only trust X-Real-IP when the direct peer is a known reverse proxy
        if (TRUSTED_PROXIES.contains(remoteAddr)) {
            String realIp = request.getHeader("X-Real-IP");
            if (StringUtils.isNotBlank(realIp)) {
                return HtmlUtils.htmlEscape(realIp);
            }
        }
        if (StringUtils.isNotBlank(remoteAddr)) {
            return HtmlUtils.htmlEscape(remoteAddr);
        }
        return "";
    }


}
