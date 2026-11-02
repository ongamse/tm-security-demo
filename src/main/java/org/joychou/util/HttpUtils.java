package org.joychou.util;

import com.squareup.okhttp.OkHttpClient;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.methods.GetMethod;
import org.apache.commons.io.IOUtils;
import org.apache.http.HttpResponse;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.nio.client.CloseableHttpAsyncClient;
import org.apache.http.impl.nio.client.HttpAsyncClients;
import org.apache.http.util.EntityUtils;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.apache.http.HttpHost;
import org.joychou.security.SafeUrl;
import org.joychou.security.SecurityUtil;
import org.joychou.security.ssrf.SSRFChecker;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.imageio.ImageIO;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.URLConnection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.*;

/**
 * @author JoyChou 2020-04-06
 */
public class HttpUtils {

    private final static Logger logger = LoggerFactory.getLogger(HttpUtils.class);

    private static final int MAX_REDIRECTS = 5;
    private static final int CONNECT_TIMEOUT_MS = 5000;
    private static final int READ_TIMEOUT_MS = 10000;

    /**
     * Redirects are never followed automatically by the Apache clients, because the redirect
     * target would not be validated.
     */
    private static final RequestConfig NO_REDIRECT_CONFIG = RequestConfig.custom()
            .setRedirectsEnabled(false)
            .setConnectTimeout(CONNECT_TIMEOUT_MS)
            .setSocketTimeout(READ_TIMEOUT_MS)
            .build();

    private static final String SSRF_BLOCKED_MSG = "[-] SSRF check failed";
    private static final String REQUEST_FAILED_MSG = "Request failed.";


    /**
     * Open a connection to the url after validating it. Redirects are followed manually and
     * every hop is validated (http/https only, no loopback/private/link-local/metadata addresses).
     *
     * @param url http request url
     * @return a connected HttpURLConnection whose response is not a redirect
     * @throws IOException if the url (or any redirect target) is not allowed
     */
    public static HttpURLConnection openValidatedConnection(String url) throws IOException {
        String current = url;
        for (int i = 0; i <= MAX_REDIRECTS; i++) {
            // the connection is built from the parsed and validated components, not from the raw text
            SafeUrl target = SSRFChecker.validate(current);
            if (target == null) {
                throw new IOException(SSRF_BLOCKED_MSG);
            }
            URLConnection urlConnection = target.toURL().openConnection();
            if (!(urlConnection instanceof HttpURLConnection)) {
                throw new IOException(SSRF_BLOCKED_MSG);
            }
            HttpURLConnection conn = (HttpURLConnection) urlConnection;
            conn.setInstanceFollowRedirects(false);
            conn.setConnectTimeout(CONNECT_TIMEOUT_MS);
            conn.setReadTimeout(READ_TIMEOUT_MS);

            int code = conn.getResponseCode(); // send request
            if (code == HttpURLConnection.HTTP_MOVED_PERM || code == HttpURLConnection.HTTP_MOVED_TEMP
                    || code == HttpURLConnection.HTTP_SEE_OTHER || code == 307 || code == 308) {
                String location = conn.getHeaderField("Location");
                conn.disconnect();
                if (location == null) {
                    throw new IOException("Redirect without Location header");
                }
                current = resolveLocation(target, location);
                continue;
            }
            return conn;
        }
        throw new IOException("Too many redirects");
    }


    /**
     * Resolve a Location header against the validated url. The result is validated again on the next hop.
     */
    private static String resolveLocation(SafeUrl base, String location) throws IOException {
        if (location.startsWith("//") || location.indexOf('\\') >= 0) {
            throw new IOException(SSRF_BLOCKED_MSG);
        }
        if (location.startsWith("/")) {
            return base.getOrigin() + location;
        }
        if (location.contains("://")) {
            return location;
        }
        throw new IOException(SSRF_BLOCKED_MSG);
    }


    /**
     * A trusted outbound destination (constant scheme, host and port).
     */
    private static final class Target {
        final String scheme;
        final String host;
        final int port;

        Target(String scheme, String host, int port) {
            this.scheme = scheme;
            this.host = host;
            this.port = port;
        }

        String origin() {
            return scheme + "://" + host + ":" + port;
        }
    }

    /**
     * Closed set of trusted outbound hosts (mirrors url/ssrf_safe_domain.xml). The destination of every
     * Apache / Jsoup request is taken from these constants, never from the request text; only a
     * validated and percent-encoded path/query is taken from the request.
     */
    private static final Map<String, Target> TRUSTED_TARGETS;

    static {
        Map<String, Target> m = new HashMap<>();
        m.put("img.alicdn.com", new Target("https", "img.alicdn.com", 443));
        TRUSTED_TARGETS = Collections.unmodifiableMap(m);
    }

    /**
     * Trusted destination plus the encoded request path of an untrusted url.
     */
    private static final class Resolved {
        final Target target;
        final String file;

        Resolved(Target target, String file) {
            this.target = target;
            this.file = file;
        }
    }


    /**
     * Validate the untrusted url (http/https, port, public host) and look its host up in the closed set
     * of trusted targets.
     *
     * @return the constant destination and the validated, encoded path/query, or null (fail closed)
     */
    private static Resolved resolveTrusted(String url) {
        SafeUrl parsed = SSRFChecker.validate(url);
        if (parsed == null) {
            return null;
        }
        Target target = TRUSTED_TARGETS.get(parsed.getHost());
        String file = SecurityUtil.safeRelativePath(parsed.getFile());
        if (target == null || file == null) {
            logger.error("[-] SSRF check failed. Host not trusted");
            return null;
        }
        return new Resolved(target, file);
    }


    /**
     * Destination for the Apache clients: the host comes from the trusted constant set and is pinned to
     * an address that was checked to be public (no second DNS lookup).
     */
    private static final class Pinned {
        final Target target;
        final String file;
        final HttpHost host;

        Pinned(Target target, String file, HttpHost host) {
            this.target = target;
            this.file = file;
            this.host = host;
        }
    }


    private static Pinned pin(String url) {
        Resolved resolved = resolveTrusted(url);
        if (resolved == null) {
            return null;
        }
        Target target = resolved.target;
        InetAddress[] addresses = SSRFChecker.resolvePublicAddresses(target.host);
        if (addresses == null) {
            return null;
        }
        return new Pinned(target, resolved.file, new HttpHost(addresses[0], target.host, target.port, target.scheme));
    }


    /**
     * Open an input stream for the validated url (see {@link #openValidatedConnection(String)}).
     *
     * @param url http request url
     */
    public static InputStream openValidatedStream(String url) throws IOException {
        return openValidatedConnection(url).getInputStream();
    }


    public static String commonHttpClient(String url) {

        Pinned pinned = pin(url);
        if (pinned == null) {
            return SSRF_BLOCKED_MSG;
        }

        HttpClient client = new HttpClient();
        // build the request from the validated components
        client.getHostConfiguration().setHost(pinned.target.host, pinned.target.port, pinned.target.scheme);
        GetMethod method = new GetMethod(pinned.file);
        method.setFollowRedirects(false);

        try {
            client.executeMethod(method); // send request
            byte[] resBody = method.getResponseBody();
            return new String(resBody);

        } catch (IOException e) {
            logger.error("request failed", e);
            return REQUEST_FAILED_MSG;
        } finally {
            // Release the connection.
            method.releaseConnection();
        }
    }


    public static String request(String url) {
        Pinned pinned = pin(url);
        if (pinned == null) {
            return SSRF_BLOCKED_MSG;
        }
        try (CloseableHttpClient client = HttpClients.custom().setDefaultRequestConfig(NO_REDIRECT_CONFIG).build()) {
            HttpGet httpGet = new HttpGet(pinned.file);
            httpGet.setConfig(NO_REDIRECT_CONFIG);
            return EntityUtils.toString(client.execute(pinned.host, httpGet).getEntity()); // send request
        } catch (Exception e) {
            logger.error("request failed", e);
            return REQUEST_FAILED_MSG;
        }
    }


    public static String httpClient(String url) {

        StringBuilder result = new StringBuilder();

        Pinned pinned = pin(url);
        if (pinned == null) {
            return SSRF_BLOCKED_MSG;
        }

        try (CloseableHttpClient client = HttpClients.createDefault()) {

            HttpGet httpGet = new HttpGet(pinned.file);
            // redirects are not followed because the target would not be validated
            httpGet.setConfig(NO_REDIRECT_CONFIG);
            HttpResponse httpResponse = client.execute(pinned.host, httpGet); // send request
            BufferedReader rd = new BufferedReader(new InputStreamReader(httpResponse.getEntity().getContent()));

            String line;
            while ((line = rd.readLine()) != null) {
                result.append(line);
            }

            return result.toString();

        } catch (Exception e) {
            logger.error("request failed", e);
            return REQUEST_FAILED_MSG;
        }
    }


    public static String URLConnection(String url) {
        try {
            HttpURLConnection urlConnection = openValidatedConnection(url);
            BufferedReader in = new BufferedReader(new InputStreamReader(urlConnection.getInputStream())); //send request
            String inputLine;
            StringBuilder html = new StringBuilder();

            while ((inputLine = in.readLine()) != null) {
                html.append(inputLine);
            }
            in.close();
            return html.toString();
        } catch (Exception e) {
            logger.error("request failed", e);
            return REQUEST_FAILED_MSG;
        }
    }


    /**
     * The default setting of followRedirects is true.
     * UserAgent is Java/1.8.0_102.
     */
    public static String HttpURLConnection(String url) {
        try {
            // validated connection; redirects are followed manually and each hop is validated
            HttpURLConnection conn = openValidatedConnection(url);
            InputStream is = conn.getInputStream();  // send request
            BufferedReader in = new BufferedReader(new InputStreamReader(is));
            String inputLine;
            StringBuilder html = new StringBuilder();

            while ((inputLine = in.readLine()) != null) {
                html.append(inputLine);
            }
            in.close();
            return html.toString();
        } catch (IOException e) {
            logger.error("request failed", e);
            return REQUEST_FAILED_MSG;
        }
    }


    /**
     * Jsoup is a HTML parser about Java.
     *
     * @param url http request url
     */
    public static String Jsoup(String url) {
        Resolved resolved = resolveTrusted(url);
        if (resolved == null) {
            return SSRF_BLOCKED_MSG;
        }
        try {
            // constant trusted origin + validated, encoded path/query
            Document doc = Jsoup.connect(resolved.target.origin() + resolved.file)
                    .followRedirects(false)
                    .timeout(3000)
                    .cookie("name", "joychou") // request cookies
                    .execute().parse();
            return doc.outerHtml();
        } catch (IOException e) {
            logger.error("request failed", e);
            return REQUEST_FAILED_MSG;
        }
    }


    /**
     * The default setting of followRedirects is true. The option of followRedirects is true.
     *
     * UserAgent is <code>okhttp/2.5.0</code>.
     */
    public static String okhttp(String url) throws IOException {
        SafeUrl target = SSRFChecker.validate(url);
        if (target == null) {
            throw new IOException(SSRF_BLOCKED_MSG);
        }
        OkHttpClient client = new OkHttpClient();
        // redirects are not followed because the target would not be validated
        client.setFollowRedirects(false);
        client.setFollowSslRedirects(false);
        com.squareup.okhttp.Request ok_http = new com.squareup.okhttp.Request.Builder().url(target.toURL()).build();
        return client.newCall(ok_http).execute().body().string();
    }


    /**
     * The default setting of followRedirects is true.
     *
     * UserAgent is Java/1.8.0_102.
     *
     * @param url http request url
     */
    public static void imageIO(String url) {
        try {
            try (InputStream is = openValidatedStream(url)) {
                ImageIO.read(is); // send request
            }
        } catch (IOException e) {
            logger.error(e.getMessage());
        }

    }


    /**
     * IOUtils which is wrapped by URLConnection can get remote pictures.
     * The default setting of redirection is true.
     *
     * @param url http request url
     */
    public static void IOUtils(String url) {
        try {
            try (InputStream is = openValidatedStream(url)) {
                IOUtils.toByteArray(is);
            }
        } catch (IOException e) {
            logger.error(e.getMessage());
        }
    }


    public static String HttpAsyncClients(String url) {
        Pinned pinned = pin(url);
        if (pinned == null) {
            return SSRF_BLOCKED_MSG;
        }
        CloseableHttpAsyncClient httpclient = HttpAsyncClients.createDefault();
        try {
            httpclient.start();
            final HttpGet request = new HttpGet(pinned.file);
            // redirects are not followed because the target would not be validated
            request.setConfig(NO_REDIRECT_CONFIG);
            Future<HttpResponse> future = httpclient.execute(pinned.host, request, null);
            HttpResponse response = future.get(6000, TimeUnit.MILLISECONDS);
            return EntityUtils.toString(response.getEntity());
        } catch (Exception e) {
            logger.error("request failed", e);
            return REQUEST_FAILED_MSG;
        } finally {
            try {
                httpclient.close();
            } catch (Exception e) {
                logger.error(e.getMessage());
            }
        }
    }
}
