package org.joychou.controller;

import org.apache.commons.lang.StringUtils;
import org.joychou.util.WebUtils;
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

    // no any proxy
    @RequestMapping("/noproxy")
    public static String noProxy(HttpServletRequest request) {
        return request.getRemoteAddr();
    }


    /**
     * Client-controlled headers such as X-Real-IP / X-Forwarded-For are spoofable,
     * so they are not trusted here. The direct peer address is used instead.
     * If a reverse proxy is deployed, configure the container (e.g. Tomcat
     * RemoteIpValve / server.forward-headers-strategy) to resolve the real ip
     * only from trusted proxies; getRemoteAddr() then returns that value.
     */
    @RequestMapping("/proxy")
    @ResponseBody
    public static String proxy(HttpServletRequest request) {
        String remoteAddr = request.getRemoteAddr();
        if (StringUtils.isNotBlank(remoteAddr)) {
            return WebUtils.escapeHtml(remoteAddr);
        }
        return "";
    }


}
