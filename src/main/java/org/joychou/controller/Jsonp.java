package org.joychou.controller;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang.StringUtils;
import org.joychou.security.SecurityUtil;
import org.joychou.util.LoginUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.util.HtmlUtils;
import org.springframework.web.servlet.view.json.MappingJackson2JsonView;
import org.joychou.config.WebConfig;

import javax.servlet.http.HttpServletRequest;
import java.security.Principal;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;


/**
 * @author JoyChou (joychou@joychou.org) @ 2018.10.24
 * https://github.com/JoyChou93/java-sec-code/wiki/JSONP
 */

@Slf4j
@RestController
@RequestMapping("/jsonp")
public class Jsonp {

    /**
     * Fixed allowlist of callback names. The request-supplied callback is only used to select one of
     * these literals; the request text itself is never written into the response body.
     */
    private static final List<String> ALLOWED_CALLBACKS = Collections.unmodifiableList(
            Arrays.asList("callback", "_callback", "cb", "jsonp", "test", "aa"));
    private static final ObjectMapper MAPPER = new ObjectMapper()
            .configure(JsonGenerator.Feature.ESCAPE_NON_ASCII, true);

    private String callback = WebConfig.getBusinessCallback();

    /**
     * Resolve the requested callback to a literal constant from the allowlist.
     * Returns null when no allowlisted callback matches.
     */
    private static String resolveCallback(String requested) {
        if (requested == null) {
            return null;
        }
        for (String allowed : ALLOWED_CALLBACKS) {
            if (allowed.equals(requested)) {
                return allowed;
            }
        }
        return null;
    }

    /**
     * Serialize the payload as JSON with HTML-significant characters written as \\uXXXX escapes
     * (non-ASCII characters are escaped by Jackson).
     */
    private static String toSafeJson(Object payload) throws JsonProcessingException {
        return MAPPER.writeValueAsString(payload)
                .replace("<", "\\u003c")
                .replace(">", "\\u003e")
                .replace("&", "\\u0026");
    }

    /**
     * Build the response: JSONP using a literal allowlisted callback name, or a plain JSON body
     * (application/json) when no allowlisted callback matches.
     */
    private static ResponseEntity<String> jsonpResponse(String requestedCallback, Object payload)
            throws JsonProcessingException {
        String json = toSafeJson(payload);
        String literalCallback = resolveCallback(requestedCallback);
        if (literalCallback == null) {
            return ResponseEntity.ok()
                    .header("X-Content-Type-Options", "nosniff")
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(json);
        }
        return ResponseEntity.ok()
                .header("X-Content-Type-Options", "nosniff")
                .contentType(MediaType.parseMediaType("application/javascript"))
                .body(literalCallback + "(" + json + ")");
    }

    private static ResponseEntity<String> errorResponse() {
        return ResponseEntity.ok()
                .header("X-Content-Type-Options", "nosniff")
                .contentType(MediaType.TEXT_PLAIN)
                .body("error");
    }

    private static ResponseEntity<String> userInfoJsonp(String cb, HttpServletRequest request)
            throws JsonProcessingException {
        return jsonpResponse(cb, JSON.parseObject(LoginUtils.getUserInfo2JsonStr(request)));
    }

    @Autowired
    CookieCsrfTokenRepository cookieCsrfTokenRepository;
    /**
     * Set the response content-type to application/javascript.
     * <p>
     * http://localhost:8080/jsonp/vuln/referer?callback_=test
     */
    @RequestMapping(value = "/vuln/referer")
    public ResponseEntity<String> referer(HttpServletRequest request) throws JsonProcessingException {
        String callback = request.getParameter(this.callback);
        return userInfoJsonp(callback, request);
    }

    /**
     * Direct access does not check Referer, non-direct access check referer.
     * Developer like to do jsonp testing like this.
     * <p>
     * http://localhost:8080/jsonp/vuln/emptyReferer?callback_=test
     */
    @RequestMapping(value = "/vuln/emptyReferer")
    public ResponseEntity<String> emptyReferer(HttpServletRequest request) throws JsonProcessingException {
        String referer = request.getHeader("referer");

        if (null != referer && SecurityUtil.checkURL(referer) == null) {
            return errorResponse();
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
    public ResponseEntity<String> safecode(HttpServletRequest request) throws JsonProcessingException {
        String referer = request.getHeader("referer");

        if (SecurityUtil.checkURL(referer) == null) {
            return errorResponse();
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
    public ResponseEntity<String> getCsrfToken2(HttpServletRequest request) throws JsonProcessingException {
        CsrfToken csrfToken = cookieCsrfTokenRepository.loadToken(request); // get csrf token

        String callback = request.getParameter("fastjsonpCallback");
        if (StringUtils.isNotBlank(callback)) {
            Map<String, String> tokenMap = null;
            if (csrfToken != null) {
                tokenMap = new LinkedHashMap<>();
                tokenMap.put("headerName", csrfToken.getHeaderName());
                tokenMap.put("parameterName", csrfToken.getParameterName());
                tokenMap.put("token", csrfToken.getToken());
            }
            return jsonpResponse(callback, tokenMap);
        } else {
            return ResponseEntity.ok()
                    .header("X-Content-Type-Options", "nosniff")
                    .contentType(MediaType.TEXT_PLAIN)
                    .body(HtmlUtils.htmlEscape(String.valueOf(csrfToken)));
        }
    }

}