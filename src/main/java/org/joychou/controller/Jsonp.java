package org.joychou.controller;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
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
import org.springframework.web.servlet.view.json.MappingJackson2JsonView;
import org.joychou.config.WebConfig;
import org.joychou.util.WebUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.Principal;
import java.util.LinkedHashMap;
import java.util.Map;


/**
 * @author JoyChou (joychou@joychou.org) @ 2018.10.24
 * https://github.com/JoyChou93/java-sec-code/wiki/JSONP
 */

@Slf4j
@RestController
@RequestMapping("/jsonp")
public class Jsonp {

    private String callback = WebConfig.getBusinessCallback();

    @Autowired
    CookieCsrfTokenRepository cookieCsrfTokenRepository;
    /**
     * Set the response content-type to application/javascript.
     * <p>
     * http://localhost:8080/jsonp/vuln/referer?callback_=test
     */
    @RequestMapping(value = "/vuln/referer", produces = JS_UTF8)
    public String referer(HttpServletRequest request, HttpServletResponse response) {
        String callback = request.getParameter(this.callback);
        return userInfoJsonp(callback, request, response);
    }

    private static final String JS_UTF8 = "application/javascript;charset=UTF-8";
    private static final String ERROR_BODY = "error";
    private static final ObjectMapper MAPPER = new ObjectMapper();

    /**
     * Wrap a Jackson-serialized object in a validated JSONP callback. Only a strict
     * JavaScript identifier is accepted as callback; the body is never built by concatenating raw values.
     */
    private static String jsonp(String callback, Object data, HttpServletResponse response) {
        response.setHeader("X-Content-Type-Options", "nosniff");
        if (!WebUtils.isValidJsonpCallback(callback)) {
            return ERROR_BODY;
        }
        try {
            // Escape characters that are legal in JSON but dangerous inside HTML / script contexts.
            String json = MAPPER.writeValueAsString(data)
                    .replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
                    .replace("\u2028", "\\u2028").replace("\u2029", "\\u2029");
            return callback + "(" + json + ")";
        } catch (JsonProcessingException e) {
            return ERROR_BODY;
        }
    }

    private static String userInfoJsonp(String callback, HttpServletRequest request, HttpServletResponse response) {
        try {
            JsonNode info = MAPPER.readTree(LoginUtils.getUserInfo2JsonStr(request));
            return jsonp(callback, info, response);
        } catch (IOException e) {
            response.setHeader("X-Content-Type-Options", "nosniff");
            return ERROR_BODY;
        }
    }

    /**
     * Direct access does not check Referer, non-direct access check referer.
     * Developer like to do jsonp testing like this.
     * <p>
     * http://localhost:8080/jsonp/vuln/emptyReferer?callback_=test
     */
    @RequestMapping(value = "/vuln/emptyReferer", produces = JS_UTF8)
    public String emptyReferer(HttpServletRequest request, HttpServletResponse response) {
        String referer = request.getHeader("referer");

        if (null != referer && SecurityUtil.checkURL(referer) == null) {
            response.setHeader("X-Content-Type-Options", "nosniff");
            return ERROR_BODY;
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
    @RequestMapping(value = "/sec/checkReferer", produces = JS_UTF8)
    public String safecode(HttpServletRequest request, HttpServletResponse response) {
        String referer = request.getHeader("referer");

        if (SecurityUtil.checkURL(referer) == null) {
            response.setHeader("X-Content-Type-Options", "nosniff");
            return ERROR_BODY;
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
    @GetMapping(value = "/fastjsonp/getToken", produces = JS_UTF8)
    public String getCsrfToken2(HttpServletRequest request, HttpServletResponse response) {
        CsrfToken csrfToken = cookieCsrfTokenRepository.loadToken(request); // get csrf token
        response.setHeader("X-Content-Type-Options", "nosniff");
        if (csrfToken == null) {
            return ERROR_BODY;
        }

        Map<String, String> data = new LinkedHashMap<>();
        data.put("headerName", csrfToken.getHeaderName());
        data.put("parameterName", csrfToken.getParameterName());
        data.put("token", csrfToken.getToken());

        String callback = request.getParameter("fastjsonpCallback");
        if (StringUtils.isNotBlank(callback)) {
            return jsonp(callback, data, response);
        }
        try {
            return MAPPER.writeValueAsString(data);
        } catch (JsonProcessingException e) {
            return ERROR_BODY;
        }
    }

}