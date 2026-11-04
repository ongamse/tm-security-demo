package org.joychou.controller;

import org.joychou.security.SecurityUtil;
import org.joychou.util.LoginUtils;
import org.joychou.util.WebUtils;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

/**
 * @author JoyChou (joychou@joychou.org) @2018.10.24
 * https://github.com/JoyChou93/java-sec-code/wiki/CORS
 */

@RestController
@RequestMapping("/cors")
public class Cors {

    private static String info = "{\"name\": \"JoyChou\", \"phone\": \"18200001111\"}";

    /**
     * Exact, immutable allowlist of origins (scheme + host + port) that may be granted CORS access.
     * The response header is always written from the matching constant in this set, never from
     * the request value.
     */
    private static final Set<String> ALLOWED_ORIGINS = Collections.unmodifiableSet(
            new HashSet<String>(Arrays.asList(
                    "https://joychou.org",
                    "https://test.joychou.org",
                    "https://joychou.com",
                    "http://localhost:8080"
            )));

    @GetMapping("/vuln/origin")
    public String vuls1(HttpServletRequest request, HttpServletResponse response) {
        String origin = request.getHeader("origin");
        if (!WebUtils.isSafeHeaderValue(origin)) {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            return "Invalid Origin header.";
        }
        // Emit CORS headers only for an exact allowlist match; write the constant, not the request value.
        for (String allowed : ALLOWED_ORIGINS) {
            if (allowed.equals(origin)) {
                response.setHeader("Access-Control-Allow-Origin", allowed);
                response.setHeader("Access-Control-Allow-Credentials", "true");  // allow cookie
                break;
            }
        }
        response.addHeader("Vary", "Origin");
        return info;
    }

    @GetMapping("/vuln/setHeader")
    public String vuls2(HttpServletRequest request, HttpServletResponse response) {
        // No wildcard: only exact allowlisted origins get a header, and never with credentials.
        String origin = request.getHeader("Origin");
        for (String allowed : ALLOWED_ORIGINS) {
            if (allowed.equals(origin)) {
                response.setHeader("Access-Control-Allow-Origin", allowed);
                break;
            }
        }
        response.addHeader("Vary", "Origin");
        return info;
    }


    @GetMapping("*")
    @RequestMapping("/vuln/crossOrigin")
    public String vuls3() {
        return info;
    }


    /**
     * 重写Cors的checkOrigin校验方法
     * 支持自定义checkOrigin，让其额外支持一级域名
     * 代码：org/joychou/security/CustomCorsProcessor
     */
    @CrossOrigin(origins = {"joychou.org", "http://test.joychou.me"})
    @GetMapping("/sec/crossOrigin")
    public String secCrossOrigin() {
        return info;
    }


    /**
     * WebMvcConfigurer设置Cors
     * 支持自定义checkOrigin
     * 代码：org/joychou/config/CorsConfig.java
     */
    @GetMapping("/sec/webMvcConfigurer")
    public CsrfToken getCsrfToken_01(CsrfToken token) {
        return token;
    }


    /**
     * spring security设置cors
     * 不支持自定义checkOrigin，因为spring security优先于setCorsProcessor执行
     * 代码：org/joychou/security/WebSecurityConfig.java
     */
    @GetMapping("/sec/httpCors")
    public CsrfToken getCsrfToken_02(CsrfToken token) {
        return token;
    }


    /**
     * 自定义filter设置cors
     * 支持自定义checkOrigin
     * 代码：org/joychou/filter/OriginFilter.java
     */
    @GetMapping("/sec/originFilter")
    public CsrfToken getCsrfToken_03(CsrfToken token) {
        return token;
    }


    /**
     * CorsFilter设置cors。
     * 不支持自定义checkOrigin，因为corsFilter优先于setCorsProcessor执行
     * 代码：org/joychou/filter/BaseCorsFilter.java
     */
    @RequestMapping("/sec/corsFilter")
    public CsrfToken getCsrfToken_04(CsrfToken token) {
        return token;
    }


    @GetMapping("/sec/checkOrigin")
    public String seccode(HttpServletRequest request, HttpServletResponse response) {
        String origin = request.getHeader("Origin");

        // 如果origin不为空并且origin不在白名单内，认定为不安全。
        // 如果origin为空，表示是同域过来的请求或者浏览器直接发起的请求。
        if (origin != null && SecurityUtil.checkURL(origin) == null) {
            return "Origin is not safe.";
        }
        if (!WebUtils.isSafeHeaderValue(origin)) {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            return "Invalid Origin header.";
        }
        // Emit CORS headers only for an exact allowlist match; write the constant, not the request value.
        for (String allowed : ALLOWED_ORIGINS) {
            if (allowed.equals(origin)) {
                response.setHeader("Access-Control-Allow-Origin", allowed);
                response.setHeader("Access-Control-Allow-Credentials", "true");
                break;
            }
        }
        response.addHeader("Vary", "Origin");
        return LoginUtils.getUserInfo2JsonStr(request);
    }


}