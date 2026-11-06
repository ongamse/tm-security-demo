package org.joychou.controller;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang.StringUtils;
import org.joychou.security.SecurityUtil;
import org.joychou.util.LoginUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.util.HtmlUtils;
import org.springframework.web.servlet.view.json.MappingJackson2JsonView;
import org.joychou.config.WebConfig;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.security.Principal;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Pattern;


/**
 * @author JoyChou (joychou@joychou.org) @ 2018.10.24
 * https://github.com/JoyChou93/java-sec-code/wiki/JSONP
 */

@Slf4j
@RestController
@RequestMapping("/jsonp")
public class Jsonp {

    private static final Pattern CALLBACK_PATTERN = Pattern.compile("^[A-Za-z_$][A-Za-z0-9_$.]{0,63}$");
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private String callback = WebConfig.getBusinessCallback();

    /**
     * Build a JSONP body: the callback name must match a strict identifier regex and the payload
     * is re-serialized with Jackson, with HTML-significant characters written as \\uXXXX escapes.
     * Returns null when the callback name is invalid.
     */
    private static String toJsonp(String cb, Object payload) throws JsonProcessingException {
        if (cb == null || !CALLBACK_PATTERN.matcher(cb).matches()) {
            return null;
        }
        String json = MAPPER.writeValueAsString(payload)
                .replace("<", "\\u003c")
                .replace(">", "\\u003e")
                .replace("&", "\\u0026");
        return cb + "(" + json + ")";
    }

    private static String userInfoJsonp(String cb, HttpServletRequest request, HttpServletResponse response)
            throws JsonProcessingException {
        response.setContentType("application/javascript");
        response.setHeader("X-Content-Type-Options", "nosniff");
        String body = toJsonp(cb, JSON.parseObject(LoginUtils.getUserInfo2JsonStr(request)));
        return body == null ? "error" : body;
    }

    @Autowired
    CookieCsrfTokenRepository cookieCsrfTokenRepository;
    /**
     * Set the response content-type to application/javascript.
     * <p>
     * http://localhost:8080/jsonp/vuln/referer?callback_=test
     */
    @RequestMapping(value = "/vuln/referer", produces = "application/javascript")
    public String referer(HttpServletRequest request, HttpServletResponse response) throws JsonProcessingException {
        String callback = request.getParameter(this.callback);
        return userInfoJsonp(callback, request, response);
    }

    /**
     * Direct access does not check Referer, non-direct access check referer.
     * Developer like to do jsonp testing like this.
     * <p>
     * http://localhost:8080/jsonp/vuln/emptyReferer?callback_=test
     */
    @RequestMapping(value = "/vuln/emptyReferer", produces = "application/javascript")
    public String emptyReferer(HttpServletRequest request, HttpServletResponse response) throws JsonProcessingException {
        String referer = request.getHeader("referer");

        if (null != referer && SecurityUtil.checkURL(referer) == null) {
            return "error";
        }
        String callback = request.getParameter(this.callback);
        return userInfoJsonp(callback, request, response);
    }

    /**
     * Adding callback or _callback on parameter can automatically return jsonp data.
     * http://localhost:8080/jsonp/object2jsonp?callback=test
     * http://localhost:8080/jsonp/object2jsonp?_callback=test
     *
     * @return Only return object, AbstractJsonpResponseBodyAdvice can be used successfully.
     * Such as JSONOjbect or JavaBean. String type cannot be used.
     */
    @RequestMapping(value = "/object2jsonp", produces = MediaType.APPLICATION_JSON_VALUE)
    public JSONObject advice(HttpServletRequest request) {
        return JSON.parseObject(LoginUtils.getUserInfo2JsonStr(request));
    }


    /**
     * http://localhost:8080/jsonp/vuln/mappingJackson2JsonView?callback=test
     * Reference: https://p0sec.net/index.php/archives/122/ from p0
     * Affected version:  java-sec-code test case version: 4.3.6
     * - Spring Framework 5.0 to 5.0.6
     * - Spring Framework 4.1 to 4.3.17
     */
    @RequestMapping(value = "/vuln/mappingJackson2JsonView", produces = MediaType.APPLICATION_JSON_VALUE)
    public ModelAndView mappingJackson2JsonView(HttpServletRequest req) {
        ModelAndView view = new ModelAndView(new MappingJackson2JsonView());
        Principal principal = req.getUserPrincipal();
        view.addObject("username", principal.getName());
        return view;
    }


    /**
     * Safe code.
     * http://localhost:8080/jsonp/sec?callback_=test
     */
    @RequestMapping(value = "/sec/checkReferer", produces = "application/javascript")
    public String safecode(HttpServletRequest request, HttpServletResponse response) throws JsonProcessingException {
        String referer = request.getHeader("referer");

        if (SecurityUtil.checkURL(referer) == null) {
            return "error";
        }
        String callback = request.getParameter(this.callback);
        return userInfoJsonp(callback, request, response);
    }

    /**
     * http://localhost:8080/jsonp/getToken?fastjsonpCallback=aa
     *
     * object to jsonp
     */
    @GetMapping("/getToken")
    public CsrfToken getCsrfToken1(CsrfToken token) {
        return token;
    }

    /**
     * http://localhost:8080/jsonp/fastjsonp/getToken?fastjsonpCallback=aa
     *
     * fastjsonp to jsonp
     */
    @GetMapping(value = "/fastjsonp/getToken", produces = "application/javascript")
    public String getCsrfToken2(HttpServletRequest request, HttpServletResponse response) throws JsonProcessingException {
        CsrfToken csrfToken = cookieCsrfTokenRepository.loadToken(request); // get csrf token

        String callback = request.getParameter("fastjsonpCallback");
        if (StringUtils.isNotBlank(callback)) {
            response.setContentType("application/javascript");
            response.setHeader("X-Content-Type-Options", "nosniff");
            Map<String, String> tokenMap = null;
            if (csrfToken != null) {
                tokenMap = new LinkedHashMap<>();
                tokenMap.put("headerName", csrfToken.getHeaderName());
                tokenMap.put("parameterName", csrfToken.getParameterName());
                tokenMap.put("token", csrfToken.getToken());
            }
            String body = toJsonp(callback, tokenMap);
            return body == null ? "error" : body;
        } else {
            return HtmlUtils.htmlEscape(String.valueOf(csrfToken));
        }
    }

}