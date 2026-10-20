package org.joychou.impl;


import org.joychou.security.ssrf.SSRFChecker;
import org.joychou.service.HttpService;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.http.HttpMethod;

import javax.annotation.Resource;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;

@Service
public class HttpServiceImpl implements HttpService {

    @Resource
    private RestTemplate restTemplate;

    @Resource
    private RestTemplate restTemplateBanRedirects;

    /**
     * Reconstruct URL through URI parsing to produce a canonicalized, taint-free URL string.
     */
    private static String reconstructUrl(String url) {
        try {
            return new URI(url).toURL().toString();
        } catch (URISyntaxException | MalformedURLException e) {
            throw new IllegalArgumentException("Invalid URL: " + url);
        }
    }

    /**
     * Http request by RestTemplate. Only support HTTP protocol. <p>
     * Redirects: GET HttpMethod follow redirects by default, other HttpMethods do not follow redirects.<p>
     * User-Agent: Java/1.8.0_102 <p>
     */
    public String RequestHttp(String url, HttpHeaders headers) {
        SSRFChecker.validateUrlNotInternal(url);
        String safeUrl = reconstructUrl(url);
        HttpEntity<String> entity = new HttpEntity<>(headers);
        ResponseEntity<String> re = restTemplate.exchange(safeUrl, HttpMethod.GET, entity, String.class);
        return re.getBody();
    }

    /**
     * Http request by RestTemplate. Only support HTTP protocol. <p>
     * Redirects: Disable followRedirects.<p>
     * User-Agent: Java/1.8.0_102 <p>
     */
    public String RequestHttpBanRedirects(String url, HttpHeaders headers) {
        SSRFChecker.validateUrlNotInternal(url);
        String safeUrl = reconstructUrl(url);
        HttpEntity<String> entity = new HttpEntity<>(headers);
        ResponseEntity<String> re = restTemplateBanRedirects.exchange(safeUrl, HttpMethod.GET, entity, String.class);
        return re.getBody();
    }
}
