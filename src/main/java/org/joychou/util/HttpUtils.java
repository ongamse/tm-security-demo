package org.joychou.util;

import com.squareup.okhttp.OkHttpClient;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.methods.GetMethod;
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
import org.apache.http.impl.nio.client.CloseableHttpAsyncClient;
import org.apache.http.impl.nio.client.HttpAsyncClients;
import org.apache.http.util.EntityUtils;
import org.jsoup.helper.HttpConnection;
import org.jsoup.nodes.Document;
import org.joychou.security.ssrf.SSRFChecker;
import org.joychou.security.ssrf.SSRFException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.imageio.ImageIO;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URI;
import java.util.concurrent.*;

/**
 * @author JoyChou 2020-04-06
 */
public class HttpUtils {

    private final static Logger logger = LoggerFactory.getLogger(HttpUtils.class);

    private static final int MAX_REDIRECTS = 5;

    /** Constant body returned to callers when an upstream request fails; never carries exception text. */
    private static final String REQUEST_FAILED = "Request failed.";

    /**
     * Resolves a host and rejects loopback, link-local, private and other internal addresses.
     * Used as the DNS resolver of the Apache clients so the check runs on the very lookup that is
     * used to connect (and on every redirect hop), which defeats DNS rebinding.
     */
    private static final DnsResolver SAFE_DNS_RESOLVER = SSRFChecker::resolveSafeAddresses;

    /**
     * Apache HttpClient whose connections can only go to public addresses.
     */
    private static CloseableHttpClient safeHttpClient() {
        Registry<ConnectionSocketFactory> registry = RegistryBuilder.<ConnectionSocketFactory>create()
                .register("http", PlainConnectionSocketFactory.getSocketFactory())
                .register("https", SSLConnectionSocketFactory.getSocketFactory())
                .build();
        PoolingHttpClientConnectionManager connectionManager =
                new PoolingHttpClientConnectionManager(registry, SAFE_DNS_RESOLVER);
        return HttpClients.custom().setConnectionManager(connectionManager).build();
    }

    /**
     * Open a stream for an untrusted http(s) url. Every hop (the url itself and each redirect target)
     * is validated by {@link SSRFChecker#requireSafeUri(String)} before it is requested, and redirects
     * are followed manually for at most {@value #MAX_REDIRECTS} hops.
     *
     * @throws org.joychou.security.ssrf.SSRFException if a hop is not a public http(s) url
     */
    public static InputStream openStream(String url) throws IOException {
        String current = url;
        for (int i = 0; i <= MAX_REDIRECTS; i++) {
            URI u = SSRFChecker.requireSafeUri(current);
            HttpURLConnection conn = (HttpURLConnection) u.toURL().openConnection();
            conn.setInstanceFollowRedirects(false);
            int code = conn.getResponseCode(); // send request
            if (code == 301 || code == 302 || code == 303 || code == 307 || code == 308) {
                String location = conn.getHeaderField("Location");
                conn.disconnect();
                if (null == location) {
                    throw new IOException("Redirect without Location header");
                }
                // absolute http(s) target, or a same-host absolute path resolved against the validated
                // URI; the next iteration re-validates the new hop
                String target = location.trim();
                if (null != SSRFChecker.parseHttpUrl(target)) {
                    current = target;
                } else if (target.startsWith("/") && !target.startsWith("//")) {
                    current = u.getScheme() + "://" + u.getRawAuthority() + target;
                } else {
                    throw new IOException("Unsupported redirect Location");
                }
                continue;
            }
            return conn.getInputStream();
        }
        throw new IOException("Too many redirects");
    }

    public static String commonHttpClient(String url) {

        HttpClient client = new HttpClient();
        GetMethod method = new GetMethod();
        try {
            // request target assembled from the components of the validated URI
            URI safeUri = SSRFChecker.requireSafeUri(url);
            client.getHostConfiguration().setHost(safeUri.getHost(), safeUri.getPort(), safeUri.getScheme());
            String path = safeUri.getRawPath();
            method.setPath(null == path || path.isEmpty() ? "/" : path);
            method.setQueryString(safeUri.getRawQuery());
        } catch (Exception e) {
            logger.error("commonHttpClient request failed, error type: {}", e.getClass().getSimpleName());
            return REQUEST_FAILED;
        }
        method.setFollowRedirects(false);

        try {
            client.executeMethod(method); // send request
            byte[] resBody = method.getResponseBody();
            return new String(resBody);

        } catch (IOException e) {
            logger.error("commonHttpClient request failed, error type: {}", e.getClass().getSimpleName());
            return REQUEST_FAILED;
        } finally {
            // Release the connection.
            method.releaseConnection();
        }
    }


    public static String request(String url) {
        try {
            URI safeUri = SSRFChecker.requireSafeUri(url);
            return Executor.newInstance(safeHttpClient()).execute(Request.Get(safeUri)).returnContent().toString();
        } catch (Exception e) {
            return e.getMessage();
        }
    }


    public static String httpClient(String url) {

        StringBuilder result = new StringBuilder();

        try {

            URI safeUri = SSRFChecker.requireSafeUri(url);
            CloseableHttpClient client = safeHttpClient();
            HttpGet httpGet = new HttpGet(safeUri);
            HttpResponse httpResponse = client.execute(httpGet); // send request
            BufferedReader rd = new BufferedReader(new InputStreamReader(httpResponse.getEntity().getContent()));

            String line;
            while ((line = rd.readLine()) != null) {
                result.append(line);
            }

            return result.toString();

        } catch (Exception e) {
            logger.error("httpClient request failed, error type: {}", e.getClass().getSimpleName());
            return REQUEST_FAILED;
        }
    }


    public static String URLConnection(String url) {
        try {
            BufferedReader in = new BufferedReader(new InputStreamReader(openStream(url))); //send request
            String inputLine;
            StringBuilder html = new StringBuilder();

            while ((inputLine = in.readLine()) != null) {
                html.append(inputLine);
            }
            in.close();
            return html.toString();
        } catch (Exception e) {
            logger.error(e.getMessage());
            return e.getMessage();
        }
    }


    /**
     * Redirects are followed manually and every hop is validated, see {@link #openStream(String)}.
     * UserAgent is Java/1.8.0_102.
     */
    public static String HttpURLConnection(String url) {
        try {
            InputStream is = openStream(url);  // send request
            BufferedReader in = new BufferedReader(new InputStreamReader(is));
            String inputLine;
            StringBuilder html = new StringBuilder();

            while ((inputLine = in.readLine()) != null) {
                html.append(inputLine);
            }
            in.close();
            return html.toString();
        } catch (IOException | SSRFException e) {
            logger.error("HttpURLConnection request failed, error type: {}", e.getClass().getSimpleName());
            return REQUEST_FAILED;
        }
    }


    /**
     * Jsoup is a HTML parser about Java.
     *
     * @param url http request url
     */
    public static String Jsoup(String url) {
        try {
            Document doc = HttpConnection.connect(SSRFChecker.requireSafeUri(url).toURL())
                    .followRedirects(false)
                    .timeout(3000)
                    .cookie("name", "joychou") // request cookies
                    .execute().parse();
            return doc.outerHtml();
        } catch (IOException | SSRFException e) {
            logger.error("Jsoup request failed, error type: {}", e.getClass().getSimpleName());
            return REQUEST_FAILED;
        }
    }


    /**
     * The default setting of followRedirects is true. The option of followRedirects is true.
     *
     * UserAgent is <code>okhttp/2.5.0</code>.
     */
    public static String okhttp(String url) throws IOException {
        OkHttpClient client = new OkHttpClient();
        client.setFollowRedirects(false);
        client.setFollowSslRedirects(false);
        com.squareup.okhttp.Request ok_http =
                new com.squareup.okhttp.Request.Builder().url(SSRFChecker.requireSafeUri(url).toURL()).build();
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
            // Only remote public http(s) pictures; block file:, jar:, internal hosts (see openStream)
            try (InputStream in = openStream(url)) { // send request
                ImageIO.read(in);
            }
        } catch (IOException | SSRFException e) {
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
            try (InputStream in = openStream(url)) { // send request
                IOUtils.toByteArray(in);
            }
        } catch (IOException | SSRFException e) {
            logger.error(e.getMessage());
        }
    }


    public static String HttpAsyncClients(String url) {
        CloseableHttpAsyncClient httpclient = HttpAsyncClients.createDefault();
        try {
            httpclient.start();
            final HttpGet request = new HttpGet(SSRFChecker.requireSafeUri(url));
            request.setConfig(RequestConfig.custom().setRedirectsEnabled(false).build());
            Future<HttpResponse> future = httpclient.execute(request, null);
            HttpResponse response = future.get(6000, TimeUnit.MILLISECONDS);
            return EntityUtils.toString(response.getEntity());
        } catch (Exception e) {
            logger.error("HttpAsyncClients request failed, error type: {}", e.getClass().getSimpleName());
            return REQUEST_FAILED;
        } finally {
            try {
                httpclient.close();
            } catch (Exception e) {
                logger.error("HttpAsyncClients close failed, error type: {}", e.getClass().getSimpleName());
            }
        }
    }
}
