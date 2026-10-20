package org.joychou.controller;

import org.apache.commons.lang.StringUtils;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.HtmlUtils;

import javax.servlet.http.HttpServletRequest;
import java.util.Collections;
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
     * Set of trusted reverse-proxy IPs. Only when the direct peer is in this
     * set do we honour the X-Real-IP header it forwards.  Extend this set (or
     * load from configuration) to match your actual proxy infrastructure.
     */
    private static final Set<String> TRUSTED_PROXIES;
    static {
        Set<String> s = new HashSet<>();
        s.add("127.0.0.1");
        s.add("::1");
        TRUSTED_PROXIES = Collections.unmodifiableSet(s);
    }

    // no any proxy
    @RequestMapping("/noproxy")
    public static String noProxy(HttpServletRequest request) {
        return HtmlUtils.htmlEscape(request.getRemoteAddr());
    }


    /**
     * Returns the client IP.  The X-Real-IP header is only trusted when the
     * direct connection comes from a known reverse proxy; otherwise the
     * peer address (remoteAddr) is used to prevent IP spoofing (CWE-290).
     */
    @RequestMapping("/proxy")
    @ResponseBody
    public static String proxy(HttpServletRequest request) {
        String remoteAddr = request.getRemoteAddr();

        // Only trust the forwarded header when the immediate peer is a known proxy
        if (TRUSTED_PROXIES.contains(remoteAddr)) {
            String forwarded = request.getHeader("X-Real-IP");
            if (StringUtils.isNotBlank(forwarded)) {
                return HtmlUtils.htmlEscape(forwarded);
            }
        }

        if (StringUtils.isNotBlank(remoteAddr)) {
            return HtmlUtils.htmlEscape(remoteAddr);
        }
        return "";
    }


}
