package org.joychou.controller;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang.StringUtils;
import org.joychou.security.SecurityUtil;
import org.joychou.util.LoginUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.view.json.MappingJackson2JsonView;
import org.joychou.config.WebConfig;
import org.joychou.util.WebUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
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
    @RequestMapping(value = "/vuln/referer", produces = "application/javascript")
    public ResponseEntity<String> referer(HttpServletRequest request) {
        String newCallback = buildCallbackName(request.getParameter(this.callback));
        if (newCallback == null) {
            return invalidCallback();
        }
        String json = JSON.toJSONString(JSON.parseObject(LoginUtils.getUserInfo2JsonStr(request)));
        return jsonpOk(newCallback, json);
    }

    /**
     * Build a new callback name from explicitly allowed characters only.
     *
     * @return the new callback name, or null if the input is not acceptable
     */
    private static String buildCallbackName(String raw) {
        if (raw == null || raw.isEmpty() || raw.length() > 64) {
            return null;
        }
        StringBuilder sb = new StringBuilder(raw.length());
        for (int i = 0; i < raw.length(); i++) {
            char c = raw.charAt(i);
            boolean letter = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
            boolean digit = c >= '0' && c <= '9';
            if (i == 0 && !(letter || c == '_' || c == '$')) {
                return null;
            }
            if (letter) {
                sb.append(c);
            } else if (digit) {
                sb.append(c);
            } else if (c == '_') {
                sb.append('_');
            } else if (c == '$') {
                sb.append('$');
            } else if (c == '.') {
                sb.append('.');
            } else {
                return null;
            }
        }
        return sb.toString();
    }

    private static ResponseEntity<String> invalidCallback() {
        return ResponseEntity.badRequest()
                .contentType(MediaType.TEXT_PLAIN)
                .header("X-Content-Type-Options", "nosniff")
                .body("invalid callback");
    }

    private static ResponseEntity<String> jsonpOk(String newCallback, String json) {
        return ResponseEntity.ok()
                .contentType(MediaType.parseMediaType("application/javascript;charset=UTF-8"))
                .header("X-Content-Type-Options", "nosniff")
                .body("/**/" + newCallback + "(" + json + ");");
    }

    /**
     * Direct access does not check Referer, non-direct access check referer.
     * Developer like to do jsonp testing like this.
     * <p>
     * http://localhost:8080/jsonp/vuln/emptyReferer?callback_=test
     */
    @RequestMapping(value = "/vuln/emptyReferer", produces = "application/javascript")
    public ResponseEntity<String> emptyReferer(HttpServletRequest request) {
        String referer = request.getHeader("referer");

        if (null != referer && SecurityUtil.checkURL(referer) == null) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .contentType(MediaType.TEXT_PLAIN)
                    .header("X-Content-Type-Options", "nosniff")
                    .body("error");
        }
        String newCallback = buildCallbackName(request.getParameter(this.callback));
        if (newCallback == null) {
            return invalidCallback();
        }
        String json = JSON.toJSONString(JSON.parseObject(LoginUtils.getUserInfo2JsonStr(request)));
        return jsonpOk(newCallback, json);
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
    public ResponseEntity<String> safecode(HttpServletRequest request) {
        String referer = request.getHeader("referer");

        if (SecurityUtil.checkURL(referer) == null) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .contentType(MediaType.TEXT_PLAIN)
                    .header("X-Content-Type-Options", "nosniff")
                    .body("error");
        }
        String newCallback = buildCallbackName(request.getParameter(this.callback));
        if (newCallback == null) {
            return invalidCallback();
        }
        String json = JSON.toJSONString(JSON.parseObject(LoginUtils.getUserInfo2JsonStr(request)));
        return jsonpOk(newCallback, json);
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
    public ResponseEntity<String> getCsrfToken2(HttpServletRequest request) {
        CsrfToken csrfToken = cookieCsrfTokenRepository.loadToken(request); // get csrf token

        String newCallback = buildCallbackName(request.getParameter("fastjsonpCallback"));
        if (newCallback == null) {
            return invalidCallback();
        }
        Map<String, String> tokenMap = new LinkedHashMap<>();
        if (csrfToken != null) {
            tokenMap.put("headerName", csrfToken.getHeaderName());
            tokenMap.put("parameterName", csrfToken.getParameterName());
            tokenMap.put("token", csrfToken.getToken());
        }
        String json = JSON.toJSONString(tokenMap);
        return jsonpOk(newCallback, json);
    }

}