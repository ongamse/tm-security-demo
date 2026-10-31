package org.joychou.controller;

import org.apache.commons.lang.StringUtils;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
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
    public static ResponseEntity<String> noProxy(HttpServletRequest request) {
        return plainText(HtmlUtils.htmlEscape(request.getRemoteAddr()));
    }

    private static ResponseEntity<String> plainText(String body) {
        return ResponseEntity.ok()
                .contentType(MediaType.parseMediaType("text/plain;charset=UTF-8"))
                .header("X-Content-Type-Options", "nosniff")
                .body(body);
    }


    /**
     * Client-supplied forwarding headers (X-Real-IP / X-Forwarded-For) are spoofable,
     * so they are not trusted. The address of the direct peer is used instead.
     * Behind a reverse proxy, configure the container to resolve the real client IP
     * from trusted proxies only (e.g. server.forward-headers-strategy / RemoteIpValve),
     * which makes getRemoteAddr() return the real client address.
     */
    @RequestMapping(value = "/proxy", produces = MediaType.TEXT_PLAIN_VALUE)
    @ResponseBody
    public static ResponseEntity<String> proxy(HttpServletRequest request) {
        String remoteAddr = request.getRemoteAddr();
        if (StringUtils.isNotBlank(remoteAddr)) {
            return plainText(HtmlUtils.htmlEscape(remoteAddr));
        }
        return plainText("");
    }


}
