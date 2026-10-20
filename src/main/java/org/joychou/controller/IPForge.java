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
     * Returns the client IP address using the direct TCP connection address
     * (request.getRemoteAddr()), which cannot be spoofed by the client.
     *
     * Note: X-Real-IP / X-Forwarded-For headers are not used here because
     * they can be forged by attackers. If behind a trusted reverse proxy,
     * configure the servlet container or a framework filter (e.g.
     * ForwardedHeaderFilter) to validate the proxy chain instead of
     * reading those headers directly in application code.
     */
    @RequestMapping("/proxy")
    @ResponseBody
    public static String proxy(HttpServletRequest request) {
        String remoteAddr = request.getRemoteAddr();
        if (StringUtils.isNotBlank(remoteAddr)) {
            return HtmlUtils.htmlEscape(remoteAddr);
        }
        return "";
    }


}
