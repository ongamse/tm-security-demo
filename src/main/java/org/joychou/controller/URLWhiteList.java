package org.joychou.controller;


import org.joychou.security.SecurityUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.util.HtmlUtils;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;

/**
 * The vulnerability code and security code of Java url whitelist.
 * The security code is checking url whitelist.
 *
 * @author JoyChou (joychou@joychou.org)
 * @version 2018.08.23
 */

@RestController
@RequestMapping("/url")
public class URLWhiteList {


    private String domainwhitelist[] = {"joychou.org", "joychou.com"};
    private static final Logger logger = LoggerFactory.getLogger(URLWhiteList.class);

    /**
     * Checks url against domain whitelist using SecurityUtil.checkURL for safe matching.
     * http://localhost:8080/url/vuln/endswith?url=http://joychou.org
     */
    @GetMapping("/vuln/endsWith")
    public String endsWith(@RequestParam("url") String url) {

        if (SecurityUtil.checkURL(url) != null) {
            return "Good url.";
        }
        return "Bad url.";
    }


    /**
     * Checks url against domain whitelist using SecurityUtil.checkURL for safe matching.
     * http://localhost:8080/url/vuln/contains?url=http://joychou.org
     */
    @GetMapping("/vuln/contains")
    public String contains(@RequestParam("url") String url) {

        if (SecurityUtil.checkURL(url) != null) {
            return "Good url.";
        }
        return "Bad url.";
    }


    /**
     * Checks url against domain whitelist using SecurityUtil.checkURL for safe matching.
     * http://localhost:8080/url/vuln/regex?url=http://joychou.org
     */
    @GetMapping("/vuln/regex")
    public String regex(@RequestParam("url") String url) {

        if (SecurityUtil.checkURL(url) != null) {
            return "Good url.";
        }
        return "Bad url.";
    }


    /**
     * Checks url against domain whitelist using SecurityUtil.checkURL before redirect.
     */
    @GetMapping("/vuln/url_bypass")
    public void url_bypass(String url, HttpServletResponse res) throws IOException {

        logger.info("url:  " + url);

        if (SecurityUtil.checkURL(url) == null) {
            res.setStatus(HttpServletResponse.SC_FORBIDDEN);
            res.getWriter().write("url forbidden");
            return;
        }

        res.sendRedirect(url);
    }


    /**
     * First-level & Multi-level host whitelist.
     * Checks url against domain whitelist using SecurityUtil.checkURL for safe matching.
     * http://localhost:8080/url/sec?url=http://aa.joychou.org
     */
    @GetMapping("/sec")
    public String sec(@RequestParam("url") String url) {

        if (SecurityUtil.checkURL(url) == null) {
            return "Bad url.";
        }

        return HtmlUtils.htmlEscape(url);
    }


    /**
     * http://localhost:8080/url/sec/array_indexOf?url=http://ccc.bbb.joychou.org
     */
    @GetMapping("/sec/array_indexOf")
    public String sec_array_indexOf(@RequestParam("url") String url) {

        // Define muti-level host whitelist.
        ArrayList<String> whiteDomainlists = new ArrayList<>();
        whiteDomainlists.add("bbb.joychou.org");
        whiteDomainlists.add("ccc.bbb.joychou.org");

        if (!SecurityUtil.isHttp(url)) {
            return "SecurityUtil is not http or https";
        }

        String host = SecurityUtil.gethost(url);

        if (whiteDomainlists.indexOf(host) != -1) {
            return "Good url.";
        }
        return "Bad url.";
    }

}
