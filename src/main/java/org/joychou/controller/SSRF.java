package org.joychou.controller;

import org.springframework.web.util.HtmlUtils;
import cn.hutool.http.HttpUtil;
import org.joychou.security.SecurityUtil;
import org.joychou.security.ssrf.SSRFChecker;
import org.joychou.security.ssrf.SSRFException;
import org.joychou.service.HttpService;
import org.joychou.util.HttpUtils;
import org.joychou.util.WebUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;

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

    @Resource
    private HttpService httpService;

    private static final String DENIED = "[-] SSRF check failed";

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
        String safeUrl = SSRFChecker.safeUrlOrNull(url);
        if (safeUrl == null) {
            return DENIED;
        }
        return HttpUtils.URLConnection(safeUrl);
    }


    @GetMapping("/urlConnection/sec")
    public String URLConnectionSec(String url) {

        // Decline not http/https protocol, unlisted hosts and internal addresses; request the rebuilt url
        String safeUrl = SSRFChecker.safeUrlOrNull(url);
        if (safeUrl == null) {
            return DENIED;
        }

        try {
            SecurityUtil.startSSRFHook();
            return HttpUtils.URLConnection(safeUrl);
        } catch (SSRFException | IOException e) {
            return e.getMessage();
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
        String safeUrl = SSRFChecker.safeUrlOrNull(url);
        if (safeUrl == null) {
            return DENIED;
        }
        try {
            SecurityUtil.startSSRFHook();
            return HttpUtils.HttpURLConnection(safeUrl);
        } catch (SSRFException | IOException e) {
            return e.getMessage();
        } finally {
            SecurityUtil.stopSSRFHook();
        }
    }


    @GetMapping("/HttpURLConnection/vuln")
    public String httpURLConnectionVuln(@RequestParam String url) {
        String safeUrl = SSRFChecker.safeUrlOrNull(url);
        if (safeUrl == null) {
            return DENIED;
        }
        return HttpUtils.HttpURLConnection(safeUrl);
    }

    /**
     * The default setting of followRedirects is true.
     * UserAgent is <code>Apache-HttpClient/4.5.12 (Java/1.8.0_102)</code>. <br>
     * <a href="http://localhost:8080/ssrf/request/sec?url=http://test.joychou.org">http://localhost:8080/ssrf/request/sec?url=http://test.joychou.org</a>
     */
    @GetMapping("/request/sec")
    public String request(@RequestParam String url) {
        String safeUrl = SSRFChecker.safeUrlOrNull(url);
        if (safeUrl == null) {
            return DENIED;
        }
        try {
            SecurityUtil.startSSRFHook();
            return HtmlUtils.htmlEscape(HttpUtils.request(safeUrl));
        } catch (SSRFException | IOException e) {
            return HtmlUtils.htmlEscape(e.getMessage());
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
            // central SSRF control: the rebuilt url is the only value that is ever requested
            String safeUrl = SSRFChecker.safeUrl(url);
            // the file name is rebuilt from letters, digits, '.', '-' and '_' only (copied from a constant)
            String downLoadImgFileName = SecurityUtil.safeFileName(
                    WebUtils.getNameWithoutExtension(safeUrl) + "." + WebUtils.getFileExtension(safeUrl));
            // download
            response.setHeader("content-disposition", "attachment;fileName=" + downLoadImgFileName);

            int length;
            byte[] bytes = new byte[1024];
            // validated (http/https, non-internal host), redirects disabled
            inputStream = SSRFChecker.openNoRedirect(safeUrl).getInputStream(); // send request
            outputStream = response.getOutputStream();
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
        String safeUrl = SSRFChecker.safeUrlOrNull(url);
        if (safeUrl == null) {
            return DENIED;
        }
        try {
            SecurityUtil.startSSRFHook();
            HttpUtils.imageIO(safeUrl);
        } catch (SSRFException | IOException e) {
            return e.getMessage();
        } finally {
            SecurityUtil.stopSSRFHook();
        }

        return "ImageIO ssrf test";
    }


    @GetMapping("/okhttp/sec")
    public String okhttp(@RequestParam String url) {

        String safeUrl = SSRFChecker.safeUrlOrNull(url);
        if (safeUrl == null) {
            return DENIED;
        }
        try {
            SecurityUtil.startSSRFHook();
            return HttpUtils.okhttp(safeUrl);
        } catch (SSRFException | IOException e) {
            return e.getMessage();
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

        String safeUrl = SSRFChecker.safeUrlOrNull(url);
        if (safeUrl == null) {
            return DENIED;
        }
        try {
            SecurityUtil.startSSRFHook();
            return HttpUtils.httpClient(safeUrl);
        } catch (SSRFException | IOException e) {
            return e.getMessage();
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

        String safeUrl = SSRFChecker.safeUrlOrNull(url);
        if (safeUrl == null) {
            return DENIED;
        }
        try {
            SecurityUtil.startSSRFHook();
            return HttpUtils.commonHttpClient(safeUrl);
        } catch (SSRFException | IOException e) {
            return e.getMessage();
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

        String safeUrl = SSRFChecker.safeUrlOrNull(url);
        if (safeUrl == null) {
            return DENIED;
        }
        try {
            SecurityUtil.startSSRFHook();
            return HttpUtils.Jsoup(safeUrl);
        } catch (SSRFException | IOException e) {
            return e.getMessage();
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
        String safeUrl = SSRFChecker.safeUrlOrNull(url);
        if (safeUrl == null) {
            return DENIED;
        }
        try {
            SecurityUtil.startSSRFHook();
            HttpUtils.IOUtils(safeUrl);
        } catch (SSRFException | IOException e) {
            return e.getMessage();
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
        String safeUrl = SSRFChecker.safeUrlOrNull(url);
        if (safeUrl == null) {
            return DENIED;
        }
        return HttpUtils.HttpAsyncClients(safeUrl);
    }


    /**
     * Only support HTTP protocol. <br>
     * GET HttpMethod follow redirects by default, other HttpMethods do not follow redirects. <br>
     * User-Agent is Java/1.8.0_102. <br>
     * <a href="http://127.0.0.1:8080/ssrf/restTemplate/vuln1?url=http://www.baidu.com">http://127.0.0.1:8080/ssrf/restTemplate/vuln1?url=http://www.baidu.com</a>
     */
    @GetMapping("/restTemplate/vuln1")
    public String RestTemplateUrlBanRedirects(String url){
        String safeUrl = SSRFChecker.safeUrlOrNull(url);
        if (safeUrl == null) {
            return DENIED;
        }
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON_UTF8);
        return httpService.RequestHttpBanRedirects(safeUrl, headers);
    }


    @GetMapping("/restTemplate/vuln2")
    public String RestTemplateUrl(String url){
        String safeUrl = SSRFChecker.safeUrlOrNull(url);
        if (safeUrl == null) {
            return DENIED;
        }
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON_UTF8);
        return httpService.RequestHttp(safeUrl, headers);
    }


    /**
     * UserAgent is Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.142 Safari/537.36 Hutool.
     * Do not follow redirects. <br>
     * <a href="http://127.0.0.1:8080/ssrf/hutool/vuln?url=http://www.baidu.com">http://127.0.0.1:8080/ssrf/hutool/vuln?url=http://www.baidu.com</a>
     */
    @GetMapping("/hutool/vuln")
    public String hutoolHttp(String url){
        String safeUrl = SSRFChecker.safeUrlOrNull(url);
        if (safeUrl == null) {
            return DENIED;
        }
        return HttpUtil.get(safeUrl);
    }


    /**
     * DnsRebind SSRF in java by setting ttl is zero. <br>
     * <a href="http://localhost:8080/ssrf/dnsrebind/vuln?url=http://test.joychou.org">http://localhost:8080/ssrf/dnsrebind/vuln?url=dnsrebind_url</a>
     */
    @GetMapping("/dnsrebind/vuln")
    public String DnsRebind(String url) {
        java.security.Security.setProperty("networkaddress.cache.negative.ttl" , "0");
        String safeUrl = SSRFChecker.safeUrlOrNull(url);
        if (safeUrl == null) {
            return "Dangerous url";
        }
        return HttpUtil.get(safeUrl);
    }


}
