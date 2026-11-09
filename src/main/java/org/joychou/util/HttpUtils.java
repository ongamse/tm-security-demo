package org.joychou.util;

import org.apache.commons.io.IOUtils;
import org.apache.http.HttpResponse;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.fluent.Executor;
import org.apache.http.client.fluent.Request;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.config.Registry;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.conn.DnsResolver;
import org.apache.http.conn.socket.ConnectionSocketFactory;
import org.apache.http.conn.socket.PlainConnectionSocketFactory;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;
import org.apache.http.util.EntityUtils;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.joychou.security.SecurityUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.imageio.ImageIO;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;

/**
 * @author JoyChou 2020-04-06
 */
public class HttpUtils {

    private final static Logger logger = LoggerFactory.getLogger(HttpUtils.class);

    private static final String ILLEGAL_URL = "Illegal url";

    private static RequestConfig noRedirectConfig() {
        return RequestConfig.custom().setRedirectsEnabled(false).build();
    }

    /**
     * Build an Apache HttpClient that can only connect to the already validated addresses of one host.
     * The host name is resolved once (in {@link SecurityUtil#resolveSafeOutboundAddresses(String)}) and the
     * connection manager is given a DnsResolver that returns exactly those addresses, so a DNS-rebinding
     * answer cannot swap in an internal address between validation and connect (TOCTOU). Redirect handling
     * is disabled, any other host name fails to resolve. TLS host name verification is unchanged because the
     * request still uses the original host name.
     *
     * @param url   the url that is going to be requested
     * @param addrs validated addresses of the url host
     * @return a client bound to the validated addresses; the caller must close it
     */
    private static CloseableHttpClient pinnedClient(String url, final InetAddress[] addrs) throws URISyntaxException {
        final String validatedHost = new URI(url).getHost();
        DnsResolver pinnedResolver = new DnsResolver() {
            @Override
            public InetAddress[] resolve(String host) throws UnknownHostException {
                if (validatedHost != null && validatedHost.equalsIgnoreCase(host)) {
                    return addrs.clone();
                }
                throw new UnknownHostException(host);
            }
        };
        Registry<ConnectionSocketFactory> registry = RegistryBuilder.<ConnectionSocketFactory>create()
                .register("http", PlainConnectionSocketFactory.getSocketFactory())
                .register("https", SSLConnectionSocketFactory.getSocketFactory())
                .build();
        PoolingHttpClientConnectionManager connManager = new PoolingHttpClientConnectionManager(registry, pinnedResolver);
        return HttpClients.custom()
                .setConnectionManager(connManager)
                .setDefaultRequestConfig(noRedirectConfig())
                .disableRedirectHandling()
                .build();
    }

    /**
     * GET a public http(s) url, connecting only to the addresses that were validated (no second DNS lookup).
     *
     * @param url http request url
     * @return the response body, or null if the url is not a safe outbound url
     */
    public static String pinnedGet(String url) {
        try {
            byte[] body = pinnedGetBytes(url);
            return body == null ? null : new String(body);
        } catch (IOException e) {
            return e.getMessage();
        }
    }

    /**
     * Same as {@link #pinnedGet(String)} but returns the raw response body.
     *
     * @param url http request url
     * @return the response body, or null if the url is not a safe outbound url
     * @throws IOException if the request fails
     */
    public static byte[] pinnedGetBytes(String url) throws IOException {
        InetAddress[] addrs = SecurityUtil.resolveSafeOutboundAddresses(url);
        if (addrs == null) {
            logger.error("Blocked outbound request to illegal url");
            return null;
        }
        try (CloseableHttpClient client = pinnedClient(url, addrs)) {
            HttpResponse httpResponse = client.execute(new HttpGet(url)); // send request
            if (httpResponse.getEntity() == null) {
                return new byte[0];
            }
            return EntityUtils.toByteArray(httpResponse.getEntity());
        } catch (URISyntaxException e) {
            throw new IOException(ILLEGAL_URL);
        }
    }

    /**
     * Send one GET to a url through the address-pinned client (redirects are NOT followed) and return the
     * redirect target of the response, so a caller can validate every hop itself.
     *
     * @param url   http request url, already validated
     * @param addrs the validated addresses of the url host, see {@link SecurityUtil#resolveSafeOutboundAddresses(String)}
     * @return the Location header of a 3xx redirect response (may be relative), otherwise null
     * @throws IOException if the request fails
     */
    public static String pinnedRedirectLocation(String url, InetAddress[] addrs) throws IOException {
        try (CloseableHttpClient client = pinnedClient(url, addrs)) {
            HttpGet httpGet = new HttpGet(url);
            httpGet.setConfig(RequestConfig.custom()
                    .setRedirectsEnabled(false)
                    .setConnectTimeout(5000)
                    .setSocketTimeout(5000)
                    .build());
            HttpResponse httpResponse = client.execute(httpGet); // send request
            int code = httpResponse.getStatusLine().getStatusCode();
            if (code >= 300 && code <= 307 && code != 304 && code != 306
                    && httpResponse.getFirstHeader("Location") != null) {
                return httpResponse.getFirstHeader("Location").getValue();
            }
            return null;
        } catch (URISyntaxException e) {
            throw new IOException(ILLEGAL_URL);
        }
    }

    private static String joinLines(byte[] body) throws IOException {
        BufferedReader in = new BufferedReader(new InputStreamReader(new ByteArrayInputStream(body)));
        StringBuilder html = new StringBuilder();
        String inputLine;
        while ((inputLine = in.readLine()) != null) {
            html.append(inputLine);
        }
        return html.toString();
    }

    public static String commonHttpClient(String url) {

        // commons-httpclient 3.1 has no pluggable DNS, so fetch through the address-pinned client.
        try {
            byte[] resBody = pinnedGetBytes(url);
            if (resBody == null) {
                return ILLEGAL_URL;
            }
            return new String(resBody);
        } catch (IOException e) {
            return "Error: " + e.getMessage();
        }
    }


    public static String request(String url) {
        InetAddress[] addrs = SecurityUtil.resolveSafeOutboundAddresses(url);
        if (addrs == null) {
            logger.error("Blocked outbound request to illegal url");
            return ILLEGAL_URL;
        }
        try (CloseableHttpClient pinned = pinnedClient(url, addrs)) {
            return Executor.newInstance(pinned).execute(Request.Get(url)).returnContent().toString();
        } catch (Exception e) {
            return e.getMessage();
        }
    }


    public static String httpClient(String url) {

        StringBuilder result = new StringBuilder();

        InetAddress[] addrs = SecurityUtil.resolveSafeOutboundAddresses(url);
        if (addrs == null) {
            logger.error("Blocked outbound request to illegal url");
            return ILLEGAL_URL;
        }

        try (CloseableHttpClient client = pinnedClient(url, addrs)) {

            HttpGet httpGet = new HttpGet(url);
            // do not follow redirects to unvalidated hosts
            httpGet.setConfig(noRedirectConfig());
            HttpResponse httpResponse = client.execute(httpGet); // send request
            BufferedReader rd = new BufferedReader(new InputStreamReader(httpResponse.getEntity().getContent()));

            String line;
            while ((line = rd.readLine()) != null) {
                result.append(line);
            }

            return result.toString();

        } catch (Exception e) {
            return e.getMessage();
        }
    }


    public static String URLConnection(String url) {
        try {
            // validate once, then connect to the validated addresses only (no second DNS lookup)
            byte[] body = pinnedGetBytes(url);
            if (body == null) {
                return ILLEGAL_URL;
            }
            return joinLines(body);
        } catch (Exception e) {
            logger.error(e.getMessage());
            return e.getMessage();
        }
    }


    /**
     * The default setting of followRedirects is true.
     * UserAgent is Java/1.8.0_102.
     */
    public static String HttpURLConnection(String url) {
        try {
            // validate once, then connect to the validated addresses only (no second DNS lookup)
            byte[] body = pinnedGetBytes(url);
            if (body == null) {
                return ILLEGAL_URL;
            }
            return joinLines(body);
        } catch (IOException e) {
            logger.error(e.getMessage());
            return e.getMessage();
        }
    }


    /**
     * Jsoup is a HTML parser about Java.
     *
     * @param url http request url
     */
    public static String Jsoup(String url) {
        try {
            // Jsoup.connect() re-resolves the host name itself, so fetch through the address-pinned
            // client and only use Jsoup as the HTML parser.
            byte[] body = pinnedGetBytes(url);
            if (body == null) {
                return ILLEGAL_URL;
            }
            Document doc = Jsoup.parse(new String(body, StandardCharsets.UTF_8), url);
            return doc.outerHtml();
        } catch (IOException e) {
            return e.getMessage();
        }
    }


    /**
     * The default setting of followRedirects is true. The option of followRedirects is true.
     *
     * UserAgent is <code>okhttp/2.5.0</code>.
     */
    public static String okhttp(String url) throws IOException {
        // OkHttp 2.5 has no pluggable DNS, so fetch through the address-pinned client.
        byte[] body = pinnedGetBytes(url);
        if (body == null) {
            throw new IOException(ILLEGAL_URL);
        }
        return new String(body, StandardCharsets.UTF_8);
    }


    /**
     * The default setting of followRedirects is true.
     *
     * UserAgent is Java/1.8.0_102.
     *
     * @param url http request url
     */
    public static void imageIO(String url) {
        // Only remote public http(s) pictures; reject file:, jar: and internal destinations.
        try {
            // validate once, then connect to the validated addresses only (no second DNS lookup)
            byte[] body = pinnedGetBytes(url);
            if (body == null) {
                return;
            }
            try (InputStream in = new ByteArrayInputStream(body)) {
                ImageIO.read(in);
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
            // validate once, then connect to the validated addresses only (no second DNS lookup)
            byte[] body = pinnedGetBytes(url);
            if (body == null) {
                return;
            }
            IOUtils.toByteArray(new ByteArrayInputStream(body));
        } catch (IOException e) {
            logger.error(e.getMessage());
        }
    }


    public static String HttpAsyncClients(String url) {
        // The async client resolves host names on its own, so fetch through the address-pinned client.
        try {
            byte[] body = pinnedGetBytes(url);
            if (body == null) {
                return ILLEGAL_URL;
            }
            return new String(body, StandardCharsets.UTF_8);
        } catch (Exception e) {
            return e.getMessage();
        }
    }
}
