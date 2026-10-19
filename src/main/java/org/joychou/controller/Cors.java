package org.joychou.controller;

import org.joychou.security.SecurityUtil;
import org.joychou.util.LoginUtils;
import org.joychou.config.WebConfig;
import java.util.ArrayList;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * @author JoyChou (joychou@joychou.org) @2018.10.24
 * https://github.com/JoyChou93/java-sec-code/wiki/CORS
 */

@RestController
@RequestMapping("/cors")
public class Cors {

    private static String info = "{\"name\": \"JoyChou\", \"phone\": \"18200001111\"}";

    @GetMapping("/vuln/origin")
    public String vuls1(HttpServletRequest request, HttpServletResponse response) {
        String origin = request.getHeader("origin");
        // Only set CORS headers when origin is present and passes the safe-domain allowlist
        if (origin != null) {
            if (SecurityUtil.checkURL(origin) == null) {
                response.setStatus(HttpServletResponse.SC_FORBIDDEN);
                return "Origin is not allowed.";
            }
            response.setHeader("Access-Control-Allow-Origin", SecurityUtil.sanitizeHeaderValue(origin));
            response.setHeader("Access-Control-Allow-Credentials", "true");
        }
        return info;
    }

    @GetMapping("/vuln/setHeader")
    public String vuls2(HttpServletRequest request, HttpServletResponse response) {
        // Validate origin against the safe-domain allowlist instead of using wildcard "*"
        String origin = request.getHeader("origin");
        if (origin != null && SecurityUtil.checkURL(origin) != null) {
            response.setHeader("Access-Control-Allow-Origin", SecurityUtil.sanitizeHeaderValue(origin));
        }
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

        // Only set CORS headers when origin is present and passes the safe-domain allowlist.
        // Null origin means same-origin or direct browser request — no CORS headers needed.
        if (origin != null) {
            if (SecurityUtil.checkURL(origin) == null) {
                return "Origin is not safe.";
            }
            response.setHeader("Access-Control-Allow-Origin", SecurityUtil.sanitizeHeaderValue(origin));
            response.setHeader("Access-Control-Allow-Credentials", "true");
        }
        return LoginUtils.getUserInfo2JsonStr(request);
    }


}