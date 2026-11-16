package org.joychou.controller;

import org.springframework.web.util.HtmlUtils;
import org.apache.commons.lang.StringUtils;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import org.springframework.beans.factory.annotation.Value;

import javax.servlet.http.HttpServletRequest;
import java.util.HashSet;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Java get real ip. More details: https://joychou.org/web/how-to-get-real-ip.html
 *
 * @author JoyChou @ 2017-12-29
 */
@RestController
@RequestMapping("/ip")
public class IPForge {

    private static final Pattern IP_LITERAL = Pattern.compile("^[0-9a-fA-F:.]{2,45}$");

    // no any proxy
    @RequestMapping("/noproxy")
    public static String noProxy(HttpServletRequest request) {
        return request.getRemoteAddr();
    }


    /**
     * Comma separated list of proxy addresses whose X-Forwarded-For header may be trusted.
     * Empty (default) means forwarding headers are never trusted.
     */
    @Value("${joychou.security.trusted.proxies:}")
    private String trustedProxies;

    /**
     * proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for
     * Client-controlled forwarding headers are only honoured when the direct peer
     * is a configured trusted proxy, and then only the right-most untrusted hop is used.
     */
    @RequestMapping("/proxy")
    @ResponseBody
    public String proxy(HttpServletRequest request) {
        String ip = resolveClientIp(request.getRemoteAddr(), request.getHeader("X-Forwarded-For"),
                parseTrusted(trustedProxies));
        if (StringUtils.isNotBlank(ip)) {
            return HtmlUtils.htmlEscape(ip);
        }
        return "";
    }

    static Set<String> parseTrusted(String config) {
        Set<String> trusted = new HashSet<String>();
        if (StringUtils.isNotBlank(config)) {
            for (String s : config.split(",")) {
                if (StringUtils.isNotBlank(s)) {
                    trusted.add(s.trim());
                }
            }
        }
        return trusted;
    }

    static String resolveClientIp(String remoteAddr, String forwardedFor, Set<String> trusted) {
        if (!trusted.contains(remoteAddr) || StringUtils.isBlank(forwardedFor)) {
            return remoteAddr;
        }
        String[] hops = forwardedFor.split(",");
        for (int i = hops.length - 1; i >= 0; i--) {
            String hop = hops[i].trim();
            if (!IP_LITERAL.matcher(hop).matches()) {
                // malformed entry: stop trusting the chain, fall back to the last verified peer
                return remoteAddr;
            }
            if (!trusted.contains(hop)) {
                return hop;
            }
        }
        return remoteAddr;
    }


}
