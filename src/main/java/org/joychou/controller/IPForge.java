package org.joychou.controller;

import org.springframework.web.util.HtmlUtils;
import org.apache.commons.lang.StringUtils;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import java.net.InetAddress;
import java.net.UnknownHostException;

/**
 * Java get real ip. More details: https://joychou.org/web/how-to-get-real-ip.html
 *
 * @author JoyChou @ 2017-12-29
 */
@RestController
@RequestMapping("/ip")
public class IPForge {

    // no any proxy
    @RequestMapping(value = "/noproxy", produces = "text/plain;charset=UTF-8")
    public static String noProxy(HttpServletRequest request) {
        return canonicalIp(request.getRemoteAddr());
    }

    /**
     * Returns the canonical textual form of a literal IPv4/IPv6 address, or "unknown".
     * Only characters valid in an IP literal are accepted, so no hostname lookup happens.
     */
    private static String canonicalIp(String addr) {
        boolean ipv4 = addr != null && addr.matches("^[0-9]{1,3}(\\.[0-9]{1,3}){3}$");
        boolean ipv6 = addr != null && addr.indexOf(':') >= 0
                && addr.matches("^[0-9A-Fa-f:.]{2,45}(%[0-9A-Za-z_.]{1,32})?$");
        if (!ipv4 && !ipv6) {
            return "unknown";
        }
        try {
            String literal = addr.indexOf('%') >= 0 ? addr.substring(0, addr.indexOf('%')) : addr;
            return InetAddress.getByName(literal).getHostAddress();
        } catch (UnknownHostException e) {
            return "unknown";
        }
    }


    /**
     * proxy_set_header X-Real-IP $remote_addr;
     * proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for
     * if code used X-Forwarded-For to get ip, the code must be vulnerable.
     */
    @RequestMapping("/proxy")
    @ResponseBody
    public static String proxy(HttpServletRequest request) {
        // Client-supplied headers (X-Real-IP / X-Forwarded-For) are spoofable; use the direct peer address.
        // If behind a trusted reverse proxy, configure the container (e.g. server.forward-headers-strategy
        // or RemoteIpValve with trusted proxies) so getRemoteAddr() reflects the real client.
        String remoteAddr = request.getRemoteAddr();
        if (StringUtils.isNotBlank(remoteAddr)) {
            return HtmlUtils.htmlEscape(remoteAddr);
        }
        return "";
    }


}
