package org.joychou.controller;

import com.google.common.net.InetAddresses;
import org.apache.commons.lang.StringUtils;
import org.springframework.http.MediaType;
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
    @RequestMapping(value = "/noproxy", produces = MediaType.TEXT_PLAIN_VALUE)
    public static String noProxy(HttpServletRequest request) {
        String remoteAddr = request.getRemoteAddr();
        if (remoteAddr != null && InetAddresses.isInetAddress(remoteAddr)) {
            return HtmlUtils.htmlEscape(remoteAddr);
        }
        return "";
    }


    /**
     * proxy_set_header X-Real-IP $remote_addr;
     * proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for
     * if code used X-Forwarded-For to get ip, the code must be vulnerable.
     */
    @RequestMapping(value = "/proxy", produces = MediaType.TEXT_PLAIN_VALUE)
    @ResponseBody
    public String proxy(HttpServletRequest request) {
        // Forwarded headers (X-Forwarded-For / X-Real-IP) are never read here: they are
        // client-controllable. Tomcat's RemoteIpValve (server.tomcat.remote-ip-header and
        // server.tomcat.internal-proxies in application.properties) rewrites getRemoteAddr()
        // only when the direct peer is a trusted internal proxy.
        String remoteAddr = request.getRemoteAddr();
        if (StringUtils.isNotBlank(remoteAddr) && InetAddresses.isInetAddress(remoteAddr)) {
            return HtmlUtils.htmlEscape(remoteAddr);
        }
        return "";
    }


}
