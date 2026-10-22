package org.joychou.controller;

import org.apache.commons.lang.StringUtils;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import org.springframework.web.util.HtmlUtils;

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
     * Headers like X-Real-IP and X-Forwarded-For are client-controlled and
     * must not be trusted without prior validation of a trusted reverse proxy
     * at the infrastructure layer (e.g. Spring's ForwardedHeaderFilter with
     * a trusted-proxy allowlist). Without that, only getRemoteAddr() is safe.
     */
    @RequestMapping("/proxy")
    @ResponseBody
    public static String proxy(HttpServletRequest request) {
        // Use the TCP-level remote address — not spoofable by the client.
        // If the app sits behind a trusted reverse proxy, configure
        // server.forward-headers-strategy=NATIVE or a ForwardedHeaderFilter
        // with a trusted-proxy allowlist so that getRemoteAddr() already
        // reflects the real client IP resolved by the container.
        String remoteAddr = request.getRemoteAddr();
        if (StringUtils.isNotBlank(remoteAddr)) {
            return HtmlUtils.htmlEscape(remoteAddr);
        }
        return "";
    }


}
