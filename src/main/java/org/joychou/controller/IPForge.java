package org.joychou.controller;

import org.joychou.security.SecurityUtil;
import org.springframework.web.util.HtmlUtils;
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
     * The address is taken only from the TCP peer; no client supplied header is read.
     */
    @RequestMapping("/proxy")
    @ResponseBody
    public String proxy(HttpServletRequest request) {
        String ip = SecurityUtil.normalizeIpLiteral(request.getRemoteAddr());
        return HtmlUtils.htmlEscape(ip == null ? "unknown" : ip);
    }


}
