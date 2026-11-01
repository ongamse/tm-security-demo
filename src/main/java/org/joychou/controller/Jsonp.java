package org.joychou.controller;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.joychou.security.SecurityUtil;
import org.joychou.util.LoginUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.view.json.MappingJackson2JsonView;
import org.joychou.config.WebConfig;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.security.Principal;
import java.util.Collections;
import java.util.HashMap;
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
    @RequestMapping(value = "/vuln/referer")
    public ResponseEntity<String> referer(HttpServletRequest request) {
        String callback = request.getParameter(this.callback);
        return userInfoJsonp(callback, request);
    }

    private static final String JS_UTF8 = "application/javascript;charset=UTF-8";
    private static final String JSON_UTF8 = "application/json;charset=UTF-8";
    private static final String TEXT_UTF8 = "text/plain;charset=UTF-8";
    private static final String ERROR_BODY = "error";
    private static final ObjectMapper MAPPER = new ObjectMapper();

    /**
     * Fixed server-side allowlist of JSONP function names. The request callback is only used as a
     * lookup key; the constant map value is what is written into the response.
     */
    private static final Map<String, String> ALLOWED_CALLBACKS;

    static {
        Map<String, String> m = new HashMap<>();
        m.put("callback", "callback");
        m.put("jsonp", "jsonp");
        m.put("cb", "cb");
        ALLOWED_CALLBACKS = Collections.unmodifiableMap(m);
    }

    private static ResponseEntity<String> body(String content, String contentType) {
        HttpHeaders headers = new HttpHeaders();
        headers.set("Content-Type", contentType);
        headers.set("X-Content-Type-Options", "nosniff");
        return new ResponseEntity<>(content, headers, HttpStatus.OK);
    }

    private static ResponseEntity<String> error() {
        return body(ERROR_BODY, TEXT_UTF8);
    }

    /**
     * Serialize an object with Jackson. When the request callback is in the server-side allowlist,
     * the constant allowlisted function name wraps the JSON; otherwise plain JSON is returned.
     * The request callback value itself is never written to the response.
     */
    private static ResponseEntity<String> jsonp(String callback, Object data) {
        try {
            // Escape characters that are legal in JSON but dangerous inside HTML / script contexts.
            String json = MAPPER.writeValueAsString(data)
                    .replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
                    .replace("\u2028", "\\u2028").replace("\u2029", "\\u2029");
            String fixedName = callback == null ? null : ALLOWED_CALLBACKS.get(callback);
            if (fixedName == null) {
                return body(json, JSON_UTF8);
            }
            return body(fixedName + "(" + json + ")", JS_UTF8);
        } catch (JsonProcessingException e) {
            return error();
        }
    }

    private static ResponseEntity<String> userInfoJsonp(String callback, HttpServletRequest request) {
        try {
            JsonNode info = MAPPER.readTree(LoginUtils.getUserInfo2JsonStr(request));
            return jsonp(callback, info);
        } catch (IOException e) {
            return error();
        }
    }

    /**
     * Direct access does not check Referer, non-direct access check referer.
     * Developer like to do jsonp testing like this.
     * <p>
     * http://localhost:8080/jsonp/vuln/emptyReferer?callback_=test
     */
    @RequestMapping(value = "/vuln/emptyReferer")
    public ResponseEntity<String> emptyReferer(HttpServletRequest request) {
        String referer = request.getHeader("referer");

        if (null != referer && SecurityUtil.checkURL(referer) == null) {
            return error();
        }
        String callback = request.getParameter(this.callback);
        return userInfoJsonp(callback, request);
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
    @RequestMapping(value = "/sec/checkReferer")
    public ResponseEntity<String> safecode(HttpServletRequest request) {
        String referer = request.getHeader("referer");

        if (SecurityUtil.checkURL(referer) == null) {
            return error();
        }
        String callback = request.getParameter(this.callback);
        return userInfoJsonp(callback, request);
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
    @GetMapping(value = "/fastjsonp/getToken")
    public ResponseEntity<String> getCsrfToken2(HttpServletRequest request) {
        CsrfToken csrfToken = cookieCsrfTokenRepository.loadToken(request); // get csrf token
        if (csrfToken == null) {
            return error();
        }

        Map<String, String> data = new LinkedHashMap<>();
        data.put("headerName", csrfToken.getHeaderName());
        data.put("parameterName", csrfToken.getParameterName());
        data.put("token", csrfToken.getToken());

        String callback = request.getParameter("fastjsonpCallback");
        return jsonp(callback, data);
    }

}