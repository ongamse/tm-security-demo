package org.joychou.controller;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;

import com.alibaba.fastjson.JSONPObject;
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
import java.nio.charset.StandardCharsets;
import java.security.Principal;


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
    @RequestMapping(value = "/vuln/referer", produces = "application/javascript;charset=UTF-8")
    public void referer(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String callback = request.getParameter(this.callback);
        writeJsonp(callback, LoginUtils.getUserInfo2JsonStr(request), response);
    }

    /**
     * Direct access does not check Referer, non-direct access check referer.
     * Developer like to do jsonp testing like this.
     * <p>
     * http://localhost:8080/jsonp/vuln/emptyReferer?callback_=test
     */
    @RequestMapping(value = "/vuln/emptyReferer", produces = "application/javascript;charset=UTF-8")
    public void emptyReferer(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String referer = request.getHeader("referer");

        if (null != referer && SecurityUtil.checkURL(referer) == null) {
            writeBody("error", response);
            return;
        }
        String callback = request.getParameter(this.callback);
        writeJsonp(callback, LoginUtils.getUserInfo2JsonStr(request), response);
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
    @RequestMapping(value = "/sec/checkReferer", produces = "application/javascript;charset=UTF-8")
    public void safecode(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String referer = request.getHeader("referer");

        if (SecurityUtil.checkURL(referer) == null) {
            writeBody("error", response);
            return;
        }
        String callback = request.getParameter(this.callback);
        writeJsonp(callback, LoginUtils.getUserInfo2JsonStr(request), response);
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
    @GetMapping(value = "/fastjsonp/getToken", produces = "application/javascript;charset=UTF-8")
    public void getCsrfToken2(HttpServletRequest request, HttpServletResponse response) throws IOException {
        CsrfToken csrfToken = cookieCsrfTokenRepository.loadToken(request); // get csrf token

        String callback = request.getParameter("fastjsonpCallback");
        if (StringUtils.isNotBlank(callback)) {
            if (!WebUtils.isValidJsonpCallback(callback)) {
                rejectCallback(response);
                return;
            }
            JSONPObject jsonpObj = new JSONPObject(WebUtils.rebuildJsonpCallback(callback));
            jsonpObj.addParameter(csrfToken);
            writeBody("/**/" + WebUtils.escapeJsonForScript(jsonpObj.toString()), response);
        } else {
            writeBody(WebUtils.escapeJsonForScript(String.valueOf(csrfToken)), response);
        }
    }

    /**
     * Validate the callback (strict identifier regex), rebuild it character by
     * character and write the escaped JSONP body. Invalid callbacks get HTTP 400.
     */
    private static void writeJsonp(String callback, String json, HttpServletResponse response) throws IOException {
        if (!WebUtils.isValidJsonpCallback(callback)) {
            rejectCallback(response);
            return;
        }
        writeBody(WebUtils.json2Jsonp(callback, json), response);
    }

    private static void writeBody(String escapedBody, HttpServletResponse response) throws IOException {
        response.setContentType("application/javascript;charset=UTF-8");
        response.setHeader("X-Content-Type-Options", "nosniff");
        // Body is already restricted to ASCII-printable chars (callback allowlisted and rebuilt,
        // JSON escaped via WebUtils.escapeJsonForScript); write raw bytes, not an HTML-aware Writer.
        byte[] bytes = escapedBody.getBytes(StandardCharsets.UTF_8);
        response.setContentLength(bytes.length);
        response.getOutputStream().write(bytes);
    }

    private static void rejectCallback(HttpServletResponse response) throws IOException {
        response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
        writeBody("/* invalid callback */", response);
    }

}
