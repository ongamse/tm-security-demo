package org.joychou.controller;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;

import com.alibaba.fastjson.JSONPObject;
import lombok.extern.slf4j.Slf4j;
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
import java.security.Principal;
import java.util.regex.Pattern;


/**
 * @author JoyChou (joychou@joychou.org) @ 2018.10.24
 * https://github.com/JoyChou93/java-sec-code/wiki/JSONP
 */

@Slf4j
@RestController
@RequestMapping("/jsonp")
public class Jsonp {

    /** Only allow valid JSONP callback names: JS identifiers optionally chained with dots. */
    private static final Pattern SAFE_JSONP_CALLBACK = Pattern.compile(
            "^[a-zA-Z_$][a-zA-Z0-9_$]*(\\.[a-zA-Z_$][a-zA-Z0-9_$]*)*$");

    private String callback = WebConfig.getBusinessCallback();

    /**
     * Validates a JSONP callback parameter. Returns the callback if it matches
     * a safe identifier pattern, or {@code null} otherwise.
     */
    private static String validateCallback(String callback) {
        if (callback == null || callback.length() > 150
                || !SAFE_JSONP_CALLBACK.matcher(callback).matches()) {
            return null;
        }
        return callback;
    }

    @Autowired
    CookieCsrfTokenRepository cookieCsrfTokenRepository;
    /**
     * Set the response content-type to application/javascript.
     * <p>
     * http://localhost:8080/jsonp/vuln/referer?callback_=test
     */
    @RequestMapping(value = "/vuln/referer", produces = "application/javascript")
    public String referer(HttpServletRequest request) {
        String callback = validateCallback(request.getParameter(this.callback));
        if (callback == null) {
            return "error";
        }
        return WebUtils.json2Jsonp(callback, LoginUtils.getUserInfo2JsonStr(request));
    }

    /**
     * Direct access does not check Referer, non-direct access check referer.
     * Developer like to do jsonp testing like this.
     * <p>
     * http://localhost:8080/jsonp/vuln/emptyReferer?callback_=test
     */
    @RequestMapping(value = "/vuln/emptyReferer", produces = "application/javascript")
    public String emptyReferer(HttpServletRequest request) {
        String referer = request.getHeader("referer");

        if (null != referer && SecurityUtil.checkURL(referer) == null) {
            return "error";
        }
        String callback = validateCallback(request.getParameter(this.callback));
        if (callback == null) {
            return "error";
        }
        return WebUtils.json2Jsonp(callback, LoginUtils.getUserInfo2JsonStr(request));
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
    public String safecode(HttpServletRequest request) {
        String referer = request.getHeader("referer");

        if (SecurityUtil.checkURL(referer) == null) {
            return "error";
        }
        String callback = validateCallback(request.getParameter(this.callback));
        if (callback == null) {
            return "error";
        }
        return WebUtils.json2Jsonp(callback, LoginUtils.getUserInfo2JsonStr(request));
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
    public String getCsrfToken2(HttpServletRequest request) {
        CsrfToken csrfToken = cookieCsrfTokenRepository.loadToken(request); // get csrf token

        String callback = validateCallback(request.getParameter("fastjsonpCallback"));
        if (callback != null) {
            JSONPObject jsonpObj = new JSONPObject(callback);
            jsonpObj.addParameter(csrfToken);
            return jsonpObj.toString();
        } else {
            return csrfToken.toString();
        }
    }

}