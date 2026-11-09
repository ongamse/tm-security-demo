package org.joychou.controller;

import cn.hutool.http.HttpUtil;
import org.joychou.security.SecurityUtil;
import org.joychou.security.ssrf.SSRFException;
import org.joychou.service.HttpService;
import org.joychou.util.HttpUtils;
import org.joychou.util.WebUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.util.HtmlUtils;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletResponse;
import java.io.*;
import java.net.*;


/**
 * Java SSRF vuln or security code.
 *
 * @author JoyChou @2017-12-28
 */

@RestController
@RequestMapping("/ssrf")
public class SSRF {

    private static final Logger logger = LoggerFactory.getLogger(SSRF.class);
    private static final String REQUEST_FAILED = "Request failed.";

    @Resource
    private HttpService httpService;

    /**
     * <p>
     *    The default setting of followRedirects is true. <br>
     *    Protocol: file ftp mailto http https jar netdoc. <br>
     *    UserAgent is Java/1.8.0_102.
     * </p>
     * <a href="http://localhost:8080/ssrf/urlConnection/vuln?url=file:///etc/passwd">http://localhost:8080/ssrf/urlConnection/vuln?url=file:///etc/passwd</a>
     */
    @RequestMapping(value = "/urlConnection/vuln", method = {RequestMethod.POST, RequestMethod.GET})
    public String URLConnectionVuln(String url) {
        return HttpUtils.URLConnection(url);
    }


    @GetMapping("/urlConnection/sec")
    public String URLConnectionSec(String url) {

        // Decline not http/https protocol
        if (!SecurityUtil.isHttp(url)) {
            return "[-] SSRF check failed";
        }

        try {
            SecurityUtil.startSSRFHook();
            return HttpUtils.URLConnection(url);
        } catch (SSRFException | IOException e) {
            logger.error("URLConnection request failed: {}", e.getClass().getName());
            return REQUEST_FAILED;
        } finally {
            SecurityUtil.stopSSRFHook();
        }

    }


    /**
     * The default setting of followRedirects is true.
     * UserAgent is Java/1.8.0_102.
     */
    @GetMapping("/HttpURLConnection/sec")
    public String httpURLConnection(@RequestParam String url) {
        try {
            SecurityUtil.startSSRFHook();
            return HttpUtils.HttpURLConnection(url);
        } catch (SSRFException | IOException e) {
            logger.error("HttpURLConnection request failed: {}", e.getClass().getName());
            return REQUEST_FAILED;
        } finally {
            SecurityUtil.stopSSRFHook();
        }
    }


    @GetMapping("/HttpURLConnection/vuln")
    public String httpURLConnectionVuln(@RequestParam String url) {
        return HttpUtils.HttpURLConnection(url);
    }

    /**
     * The default setting of followRedirects is true.
     * UserAgent is <code>Apache-HttpClient/4.5.12 (Java/1.8.0_102)</code>. <br>
     * <a href="http://localhost:8080/ssrf/request/sec?url=http://test.joychou.org">http://localhost:8080/ssrf/request/sec?url=http://test.joychou.org</a>
     */
    @GetMapping("/request/sec")
    public String request(@RequestParam String url) {
        try {
            SecurityUtil.startSSRFHook();
            return HtmlUtils.htmlEscape(HttpUtils.request(url));
        } catch (SSRFException | IOException e) {
            logger.error("request failed: {}", e.getClass().getName());
            return REQUEST_FAILED;
        } finally {
            SecurityUtil.stopSSRFHook();
        }
    }


    /**
     * Download the url file. <br>
     * <code>new URL(String url).openConnection()</code>  <br>
     * <code>new URL(String url).openStream()</code> <br>
     * <code>new URL(String url).getContent()</code> <br>
     * <a href="http://localhost:8080/ssrf/openStream?url=file:///etc/passwd">http://localhost:8080/ssrf/openStream?url=file:///etc/passwd</a>

     */
    @GetMapping("/openStream")
    public void openStream(@RequestParam String url, HttpServletResponse response) throws IOException {
        InputStream inputStream = null;
        OutputStream outputStream = null;
        try {
            String downLoadImgFileName = WebUtils.getNameWithoutExtension(url) + "." + WebUtils.getFileExtension(url);
            // download
            response.setHeader("content-disposition", "attachment;fileName=" + SecurityUtil.encodeHeaderValue(downLoadImgFileName));

            // Only public http(s) destinations; the host is resolved once and the validated address is
            // the one connected to; redirects are not followed.
            byte[] body = HttpUtils.pinnedGetBytes(url);
            if (body == null) {
                logger.error("Blocked openStream to illegal url");
                response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                return;
            }
            inputStream = new ByteArrayInputStream(body);
            outputStream = response.getOutputStream();
            int length;
            byte[] bytes = new byte[1024];
            while ((length = inputStream.read(bytes)) > 0) {
                outputStream.write(bytes, 0, length);
            }

        } catch (Exception e) {
            logger.error(e.toString());
        } finally {
            if (inputStream != null) {
                inputStream.close();
            }
            if (outputStream != null) {
                outputStream.close();
            }
        }
    }


    /**
     * The default setting of followRedirects is true.
     * UserAgent is Java/1.8.0_102.
     */
    @GetMapping("/ImageIO/sec")
    public String ImageIO(@RequestParam String url) {
        try {
            SecurityUtil.startSSRFHook();
            HttpUtils.imageIO(url);
        } catch (SSRFException | IOException e) {
            logger.error("ImageIO request failed: {}", e.getClass().getName());
            return REQUEST_FAILED;
        } finally {
            SecurityUtil.stopSSRFHook();
        }

        return "ImageIO ssrf test";
    }


    @GetMapping("/okhttp/sec")
    public String okhttp(@RequestParam String url) {

        try {
            SecurityUtil.startSSRFHook();
            return HttpUtils.okhttp(url);
        } catch (SSRFException | IOException e) {
            logger.error("okhttp request failed: {}", e.getClass().getName());
            return REQUEST_FAILED;
        } finally {
            SecurityUtil.stopSSRFHook();
        }

    }

    /**
     * The default setting of followRedirects is true.
     * UserAgent is <code>Apache-HttpClient/4.5.12 (Java/1.8.0_102)</code>. <br>
     * <a href="http://localhost:8080/ssrf/httpclient/sec?url=http://www.baidu.com">http://localhost:8080/ssrf/httpclient/sec?url=http://www.baidu.com</a>
     */
    @GetMapping("/httpclient/sec")
    public String HttpClient(@RequestParam String url) {

        try {
            SecurityUtil.startSSRFHook();
            return HttpUtils.httpClient(url);
        } catch (SSRFException | IOException e) {
            logger.error("httpClient request failed: {}", e.getClass().getName());
            return REQUEST_FAILED;
        } finally {
            SecurityUtil.stopSSRFHook();
        }

    }


    /**
     * The default setting of followRedirects is true.
     * UserAgent is <code>Jakarta Commons-HttpClient/3.1</code>.
     * <a href="http://localhost:8080/ssrf/commonsHttpClient/sec?url=http://www.baidu.com">http://localhost:8080/ssrf/commonsHttpClient/sec?url=http://www.baidu.com</a>
     */
    @GetMapping("/commonsHttpClient/sec")
    public String commonsHttpClient(@RequestParam String url) {

        try {
            SecurityUtil.startSSRFHook();
            return HttpUtils.commonHttpClient(url);
        } catch (SSRFException | IOException e) {
            logger.error("commonsHttpClient request failed: {}", e.getClass().getName());
            return REQUEST_FAILED;
        } finally {
            SecurityUtil.stopSSRFHook();
        }

    }

    /**
     * The default setting of followRedirects is true.
     * UserAgent is the useragent of browser.<br>
     * <a href="http://localhost:8080/ssrf/Jsoup?url=http://www.baidu.com">http://localhost:8080/ssrf/Jsoup?url=http://www.baidu.com</a>
     */
    @GetMapping("/Jsoup/sec")
    public String Jsoup(@RequestParam String url) {

        try {
            SecurityUtil.startSSRFHook();
            return HttpUtils.Jsoup(url);
        } catch (SSRFException | IOException e) {
            logger.error("Jsoup request failed: {}", e.getClass().getName());
            return REQUEST_FAILED;
        } finally {
            SecurityUtil.stopSSRFHook();
        }

    }


    /**
     * The default setting of followRedirects is true.
     * UserAgent is <code>Java/1.8.0_102</code>. <br>
     * <a href="http://localhost:8080/ssrf/IOUtils/sec?url=http://www.baidu.com">http://localhost:8080/ssrf/IOUtils/sec?url=http://www.baidu.com</a>
     */
    @GetMapping("/IOUtils/sec")
    public String IOUtils(String url) {
        try {
            SecurityUtil.startSSRFHook();
            HttpUtils.IOUtils(url);
        } catch (SSRFException | IOException e) {
            logger.error("IOUtils request failed: {}", e.getClass().getName());
            return REQUEST_FAILED;
        } finally {
            SecurityUtil.stopSSRFHook();
        }

        return "IOUtils ssrf test";
    }


    /**
     * The default setting of followRedirects is true.
     * UserAgent is <code>Apache-HttpAsyncClient/4.1.4 (Java/1.8.0_102)</code>.
     */
    @GetMapping("/HttpSyncClients/vuln")
    public String HttpSyncClients(@RequestParam("url") String url) {
        return HttpUtils.HttpAsyncClients(url);
    }


    /**
     * Only support HTTP protocol. <br>
     * GET HttpMethod follow redirects by default, other HttpMethods do not follow redirects. <br>
     * User-Agent is Java/1.8.0_102. <br>
     * <a href="http://127.0.0.1:8080/ssrf/restTemplate/vuln1?url=http://www.baidu.com">http://127.0.0.1:8080/ssrf/restTemplate/vuln1?url=http://www.baidu.com</a>
     */
    @GetMapping("/restTemplate/vuln1")
    public String RestTemplateUrlBanRedirects(String url){
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON_UTF8);
        return httpService.RequestHttpBanRedirects(url, headers);
    }


    @GetMapping("/restTemplate/vuln2")
    public String RestTemplateUrl(String url){
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON_UTF8);
        return httpService.RequestHttp(url, headers);
    }


    /**
     * UserAgent is Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.142 Safari/537.36 Hutool.
     * Do not follow redirects. <br>
     * <a href="http://127.0.0.1:8080/ssrf/hutool/vuln?url=http://www.baidu.com">http://127.0.0.1:8080/ssrf/hutool/vuln?url=http://www.baidu.com</a>
     */
    @GetMapping("/hutool/vuln")
    public String hutoolHttp(String url){
        return HttpUtil.get(url);
    }


    /**
     * DnsRebind SSRF in java by setting ttl is zero. <br>
     * <a href="http://localhost:8080/ssrf/dnsrebind/vuln?url=http://test.joychou.org">http://localhost:8080/ssrf/dnsrebind/vuln?url=dnsrebind_url</a>
     */
    @GetMapping("/dnsrebind/vuln")
    public String DnsRebind(String url) {
        // The request value is only a lookup key into a fixed server-side allowlist: the remote resource that
        // is fetched always comes from DNSREBIND_TARGETS, never from the request itself.
        String target = resolveDnsRebindTarget(url);
        if (target == null) {
            return "Dangerous url";
        }
        // Validation and request must use the same DNS answer: HttpUtils.pinnedGet resolves the host once,
        // rejects internal addresses and connects to exactly the validated addresses.
        String body = HttpUtils.pinnedGet(target);
        if (body == null) {
            return "Dangerous url";
        }
        return body;
    }

    /**
     * Server-side allowlist of remote resources the DnsRebind demo endpoint may fetch (short key or the
     * exact destination url -> constant destination url).
     */
    private static final java.util.Map<String, String> DNSREBIND_TARGETS;

    static {
        java.util.Map<String, String> targets = new java.util.HashMap<String, String>();
        targets.put("test-joychou-org", "http://test.joychou.org");
        targets.put("http://test.joychou.org", "http://test.joychou.org");
        DNSREBIND_TARGETS = java.util.Collections.unmodifiableMap(targets);
    }

    /**
     * @param key untrusted key supplied by the client
     * @return the allowlisted destination constant, or null when the key is not allowlisted (fail closed)
     */
    private static String resolveDnsRebindTarget(String key) {
        if (key == null) {
            return null;
        }
        for (java.util.Map.Entry<String, String> entry : DNSREBIND_TARGETS.entrySet()) {
            if (entry.getKey().equals(key)) {
                return entry.getValue();
            }
        }
        return null;
    }


}
