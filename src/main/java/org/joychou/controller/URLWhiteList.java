package org.joychou.controller;


import org.joychou.security.SecurityUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.util.HtmlUtils;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
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

    /** Exact (equals) host allowlist for redirect targets. */
    private static final Set<String> REDIRECT_ALLOWED_HOSTS = Collections.unmodifiableSet(
            new HashSet<String>(Arrays.asList("joychou.org", "www.joychou.org", "test.joychou.org",
                    "joychou.com", "www.joychou.com", "localhost")));

    private static boolean hasUnsafeRedirectChars(String s) {
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c < 0x20 || c == 0x7f || c == '\\') {
                return true;
            }
        }
        return false;
    }

    /**
     * bypass poc: bypassjoychou.org
     * http://localhost:8080/url/vuln/endswith?url=http://aaajoychou.org
     */
    @GetMapping("/vuln/endsWith")
    public String endsWith(@RequestParam("url") String url) {

        String host = SecurityUtil.gethost(url);

        for (String domain : domainwhitelist) {
            if (host.endsWith(domain)) {
                return "Good url.";
            }
        }
        return "Bad url.";
    }


    /**
     * It's the same with <code>indexOf</code>.
     * <p>
     * http://localhost:8080/url/vuln/contains?url=http://joychou.org.bypass.com
     * http://localhost:8080/url/vuln/contains?url=http://bypassjoychou.org
     */
    @GetMapping("/vuln/contains")
    public String contains(@RequestParam("url") String url) {

        String host = SecurityUtil.gethost(url);

        for (String domain : domainwhitelist) {
            if (host.contains(domain)) {
                return "Good url.";
            }
        }
        return "Bad url.";
    }


    /**
     * bypass poc: bypassjoychou.org. It's the same with endsWith.
     * http://localhost:8080/url/vuln/regex?url=http://aaajoychou.org
     */
    @GetMapping("/vuln/regex")
    public String regex(@RequestParam("url") String url) {

        String host = SecurityUtil.gethost(url);
        Pattern p = Pattern.compile("joychou\\.org$");
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

        logger.info("url_bypass request received");

        if (!SecurityUtil.isHttp(url)) {
            return;
        }

        // Gate right at the sink: java.net.URI string parsing only (no network I/O), http/https scheme,
        // no userinfo, non-empty host. Rejected urls are never fetched or redirected to.
        URI parsed;
        try {
            parsed = new URI(url);
        } catch (URISyntaxException e) {
            res.setStatus(HttpServletResponse.SC_FORBIDDEN);
            return;
        }
        String scheme = parsed.getScheme();
        String uriHost = parsed.getHost();
        if (scheme == null || !("http".equalsIgnoreCase(scheme) || "https".equalsIgnoreCase(scheme))
                || parsed.getRawUserInfo() != null || uriHost == null || uriHost.isEmpty()) {
            res.setStatus(HttpServletResponse.SC_FORBIDDEN);
            return;
        }
        // The host comes from the strict java.net.URI parser only (java.net.URL is not used here).
        String host = uriHost.toLowerCase();
        logger.info("url_bypass host parsed");

        // endsWith .
        for (String domain : domainwhitelist) {
            if (host.endsWith("." + domain)) {
                // Re-validate before redirecting: exact host allowlist, no backslash/control
                // characters, and the configured URI-based allowlist. Reject, never sanitise.
                if (!REDIRECT_ALLOWED_HOSTS.contains(host) || hasUnsafeRedirectChars(url)
                        || SecurityUtil.checkURL(url) == null) {
                    res.setStatus(HttpServletResponse.SC_FORBIDDEN);
                    return;
                }
                // Redirect to the parsed URI (ASCII form), never the raw request string.
                res.sendRedirect(parsed.toASCIIString());
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
