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
        String peer = request.getRemoteAddr();
        Set<String> trusted = parseTrusted(trustedProxies);
        String ip = peer;
        // The forwarding header is only read when the direct peer is a configured trusted proxy.
        if (isTrustedPeer(peer, trusted)) {
            ip = resolveClientIp(peer, request.getHeader("X-Forwarded-For"), trusted);
        }
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

    static boolean isTrustedPeer(String remoteAddr, Set<String> trusted) {
        String peer = normalizeIp(remoteAddr);
        return peer != null && normalizedSet(trusted).contains(peer);
    }

    static String resolveClientIp(String remoteAddr, String forwardedFor, Set<String> trusted) {
        if (!isTrustedPeer(remoteAddr, trusted) || StringUtils.isBlank(forwardedFor)) {
            return remoteAddr;
        }
        Set<String> trustedNorm = normalizedSet(trusted);
        String[] hops = forwardedFor.split(",");
        for (int i = hops.length - 1; i >= 0; i--) {
            // the hop is parsed into numbers and rebuilt; the header text itself is never returned
            String hop = normalizeIp(hops[i]);
            if (hop == null) {
                // malformed entry: stop trusting the chain, fall back to the last verified peer
                return remoteAddr;
            }
            if (!trustedNorm.contains(hop)) {
                return hop;
            }
        }
        return remoteAddr;
    }

    private static Set<String> normalizedSet(Set<String> addrs) {
        Set<String> out = new HashSet<String>();
        for (String a : addrs) {
            String n = normalizeIp(a);
            if (n != null) {
                out.add(n);
            }
        }
        return out;
    }

    /**
     * Strictly parses an IPv4 or IPv6 literal (no zone, no embedded IPv4, no leading zeros in
     * IPv4 octets) and rebuilds the canonical text from the parsed integers.
     * Returns null when the input is not a valid literal.
     */
    static String normalizeIp(String raw) {
        if (raw == null) {
            return null;
        }
        String s = raw.trim();
        if (!IP_LITERAL.matcher(s).matches()) {
            return null;
        }
        if (s.indexOf(':') < 0) {
            return normalizeIpv4(s);
        }
        return normalizeIpv6(s);
    }

    private static String normalizeIpv4(String s) {
        String[] parts = s.split("\\.", -1);
        if (parts.length != 4) {
            return null;
        }
        int[] octets = new int[4];
        for (int i = 0; i < 4; i++) {
            String p = parts[i];
            if (!p.matches("[0-9]{1,3}") || (p.length() > 1 && p.charAt(0) == '0')) {
                return null;
            }
            octets[i] = Integer.parseInt(p);
            if (octets[i] > 255) {
                return null;
            }
        }
        return octets[0] + "." + octets[1] + "." + octets[2] + "." + octets[3];
    }

    private static String normalizeIpv6(String s) {
        if (s.indexOf('.') >= 0) {
            return null;
        }
        int gap = s.indexOf("::");
        if (gap != s.lastIndexOf("::")) {
            return null;
        }
        int[] groups = new int[8];
        if (gap < 0) {
            int[] all = parseHextets(s);
            if (all == null || all.length != 8) {
                return null;
            }
            groups = all;
        } else {
            int[] head = parseHextets(s.substring(0, gap));
            int[] tail = parseHextets(s.substring(gap + 2));
            if (head == null || tail == null || head.length + tail.length > 7) {
                return null;
            }
            System.arraycopy(head, 0, groups, 0, head.length);
            System.arraycopy(tail, 0, groups, 8 - tail.length, tail.length);
        }
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 8; i++) {
            if (i > 0) {
                sb.append(':');
            }
            sb.append(Integer.toHexString(groups[i]));
        }
        return sb.toString();
    }

    private static int[] parseHextets(String s) {
        if (s.isEmpty()) {
            return new int[0];
        }
        String[] parts = s.split(":", -1);
        int[] out = new int[parts.length];
        for (int i = 0; i < parts.length; i++) {
            if (!parts[i].matches("[0-9a-fA-F]{1,4}")) {
                return null;
            }
            out[i] = Integer.parseInt(parts[i], 16);
        }
        return out;
    }


}
