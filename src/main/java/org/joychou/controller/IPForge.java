package org.joychou.controller;

import org.springframework.web.util.HtmlUtils;
import org.apache.commons.lang.StringUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import java.util.regex.Pattern;

/**
 * Java get real ip. More details: https://joychou.org/web/how-to-get-real-ip.html
 *
 * @author JoyChou @ 2017-12-29
 */
@RestController
@RequestMapping("/ip")
public class IPForge {

    // no any proxy
    private static final Pattern IPV4_PATTERN = Pattern.compile(
            "^((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\\.){3}(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])$");
    // IPv6 literal (optionally with embedded IPv4 tail); at least two colons, hex digits / colons / dots only.
    private static final Pattern IPV6_PATTERN = Pattern.compile(
            "^(?=(?:[^:]*:){2})[0-9A-Fa-f:.]{2,45}$");

    // no any proxy
    @RequestMapping(value = "/noproxy", produces = "text/plain;charset=UTF-8")
    public ResponseEntity<String> noProxy(HttpServletRequest request) {
        String remoteAddr = request.getRemoteAddr();
        // Strip an IPv6 zone id (e.g. fe80::1%eth0) before the strict literal check.
        String addr = remoteAddr == null ? "" : remoteAddr.replaceFirst("%[0-9A-Za-z._-]{1,32}$", "");
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.parseMediaType("text/plain;charset=UTF-8"));
        headers.add("X-Content-Type-Options", "nosniff");
        if (!IPV4_PATTERN.matcher(addr).matches() && !IPV6_PATTERN.matcher(addr).matches()) {
            return new ResponseEntity<>("invalid address", headers, HttpStatus.BAD_REQUEST);
        }
        return new ResponseEntity<>(HtmlUtils.htmlEscape(addr), headers, HttpStatus.OK);
    }


    /**
     * proxy_set_header X-Real-IP $remote_addr;
     * proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for
     * if code used X-Forwarded-For to get ip, the code must be vulnerable.
     */
    @RequestMapping("/proxy")
    @ResponseBody
    public static String proxy(HttpServletRequest request) {
        // Do not trust client-supplied forwarding headers (X-Real-IP / X-Forwarded-For).
        // Use the socket peer address; a trusted-proxy mechanism (e.g. Tomcat RemoteIpValve)
        // should be configured at the server level if the app runs behind a reverse proxy.
        String remoteAddr = request.getRemoteAddr();
        if (StringUtils.isNotBlank(remoteAddr)) {
            return HtmlUtils.htmlEscape(remoteAddr);
        }
        return "";
    }


}
