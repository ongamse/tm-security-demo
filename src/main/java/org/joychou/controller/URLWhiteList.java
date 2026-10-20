package org.joychou.controller;


import org.joychou.security.SecurityUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.util.HtmlUtils;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

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
     * Fixed: require exact match or subdomain match with dot prefix.
     */
    @GetMapping("/vuln/endsWith")
    public String endsWith(@RequestParam("url") String url) {

        if (!SecurityUtil.isHttp(url)) {
            return "Bad url.";
        }

        String host = SecurityUtil.gethost(url);

        for (String domain : domainwhitelist) {
            if (host.equals(domain) || host.endsWith("." + domain)) {
                return "Good url.";
            }
        }
        return "Bad url.";
    }


    /**
     * Fixed: use exact match or subdomain match instead of contains.
     */
    @GetMapping("/vuln/contains")
    public String contains(@RequestParam("url") String url) {

        if (!SecurityUtil.isHttp(url)) {
            return "Bad url.";
        }

        String host = SecurityUtil.gethost(url);

        for (String domain : domainwhitelist) {
            if (host.equals(domain) || host.endsWith("." + domain)) {
                return "Good url.";
            }
        }
        return "Bad url.";
    }


    /**
     * Fixed: regex anchored to match exact domain or subdomain only.
     */
    @GetMapping("/vuln/regex")
    public String regex(@RequestParam("url") String url) {

        if (!SecurityUtil.isHttp(url)) {
            return "Bad url.";
        }

        String host = SecurityUtil.gethost(url);
        // Match exactly "joychou.org" or any subdomain "*.joychou.org"
        Pattern p = Pattern.compile("^(.*\\.)?joychou\\.org$");
        Matcher m = p.matcher(host);

        if (m.find()) {
            return "Good url.";
        } else {
            return "Bad url.";
        }
    }


    /**
     * The bypass of using {@link java.net.URL} to getHost.
     * <p>
     * <a href="http://localhost:8080/url/vuln/url_bypass?url=http://evil.com%5c@www.joychou.org/a.html">bypass 1</a>
     * <a href="http://localhost:8080/url/vuln/url_bypass?url=http://evil.com%5cwww.joychou.org/a.html">bypass 2</a>
     *
     * <p>
     * <a href="https://github.com/JoyChou93/java-sec-code/wiki/URL-whtielist-Bypass">More details</a>
     */
    @GetMapping("/vuln/url_bypass")
    public void url_bypass(String url, HttpServletResponse res) throws IOException {

        logger.info("url:  " + url);

        if (!SecurityUtil.isHttp(url)) {
            return;
        }

        // Use URI instead of URL to avoid host parsing bypass
        String host = SecurityUtil.gethost(url);
        logger.info("host:  " + host);

        for (String domain : domainwhitelist) {
            if (host.equals(domain) || host.endsWith("." + domain)) {
                res.sendRedirect(url);
                return;
            }
        }

    }


    /**
     * First-level & Multi-level host whitelist.
     * http://localhost:8080/url/sec?url=http://aa.joychou.org
     */
    @GetMapping("/sec")
    public String sec(@RequestParam("url") String url) {

        String whiteDomainlists[] = {"joychou.org", "joychou.com", "test.joychou.me"};

        if (!SecurityUtil.isHttp(url)) {
            return "SecurityUtil is not http or https";
        }

        String host = SecurityUtil.gethost(url);

        for (String whiteHost: whiteDomainlists){
            if (whiteHost.startsWith(".") && host.endsWith(whiteHost)) {
                return HtmlUtils.htmlEscape(url);
            } else if (!whiteHost.startsWith(".") && host.equals(whiteHost)) {
                return HtmlUtils.htmlEscape(url);
            }
        }

        return "Bad url.";
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
