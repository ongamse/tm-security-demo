package org.joychou.controller;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;

/**
 * Java get real ip. More details: https://joychou.org/web/how-to-get-real-ip.html
 *
 * Client-controlled headers (X-Forwarded-For, X-Real-IP, ...) are never used to derive
 * the client address here, because any caller can forge them.
 *
 * @author JoyChou @ 2017-12-29
 */
@RestController
@RequestMapping("/ip")
public class IPForge {

    // no any proxy
    @RequestMapping("/noproxy")
    public static String noProxy(HttpServletRequest request) {
        // The address is intentionally not reflected into the response body.
        return "ok";
    }


    /**
     * The client address must come from the TCP peer only (request.getRemoteAddr()).
     * Behind a reverse proxy, configure the container (e.g. server.use-forward-headers /
     * RemoteIpValve with an internal-proxies allowlist) instead of reading headers in code.
     */
    @RequestMapping("/proxy")
    @ResponseBody
    public String proxy(HttpServletRequest request) {
        // The address is intentionally not reflected into the response body.
        return "ok";
    }

}
