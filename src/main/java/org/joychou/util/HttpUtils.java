package org.joychou.util;

import com.squareup.okhttp.OkHttpClient;
import org.apache.commons.httpclient.HostConfiguration;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.methods.GetMethod;
import org.apache.commons.httpclient.protocol.Protocol;
import org.apache.commons.io.IOUtils;
import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.fluent.Executor;
import org.apache.http.client.fluent.Request;
import org.apache.http.client.methods.CloseableHttpResponse;
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
import org.joychou.security.ssrf.SSRFChecker;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.imageio.ImageIO;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URLConnection;
import java.util.concurrent.*;

/**
 * @author JoyChou 2020-04-06
 */
public class HttpUtils {

    private final static Logger logger = LoggerFactory.getLogger(HttpUtils.class);
    private static final int MAX_REDIRECTS = 5;
    private static final int CONNECT_TIMEOUT_MS = 5000;
    private static final int READ_TIMEOUT_MS = 10000;
    private static final int MAX_IMAGE_BYTES = 5 * 1024 * 1024;

    /**
     * The single entry point that turns an untrusted url string into something that may be
     * requested: a server-constructed URI rebuilt from validated components (see
     * {@link SSRFChecker#canonicalize(String)}). Every sink below uses only the returned URI.
     */
    private static URI safeUri(String url) throws IOException {
        URI uri = SSRFChecker.canonicalize(url);
        if (uri == null) {
            throw new IOException("SSRF check failed: illegal url");
        }
        return uri;
    }

    private static boolean isRedirect(int code) {
        return code == 301 || code == 302 || code == 303 || code == 307 || code == 308;
    }

    /**
     * Validate the next hop of a redirect (absolute http(s) or same-origin absolute path).
     */
    private static URI nextHop(URI current, String location) throws IOException {
        if (location == null) {
            throw new IOException("Redirect without Location header");
        }
        URI next = SSRFChecker.resolveRedirect(current, location);
        if (next == null) {
            throw new IOException("SSRF check failed: illegal redirect target");
        }
        return next;
    }

    /**
     * Apache HttpClient 4.x that never follows redirects by itself and validates the resolved
     * addresses again at connect time (so a DNS answer that changed after the check is refused).
     */
    private static CloseableHttpClient newSafeApacheClient() {
        Registry<ConnectionSocketFactory> registry = RegistryBuilder.<ConnectionSocketFactory>create()
                .register("http", PlainConnectionSocketFactory.getSocketFactory())
                .register("https", SSLConnectionSocketFactory.getSocketFactory())
                .build();
        DnsResolver dnsResolver = SSRFChecker::resolvePublic;
        PoolingHttpClientConnectionManager cm = new PoolingHttpClientConnectionManager(registry, dnsResolver);
        RequestConfig config = RequestConfig.custom()
                .setRedirectsEnabled(false)
                .setConnectTimeout(CONNECT_TIMEOUT_MS)
                .setSocketTimeout(READ_TIMEOUT_MS)
                .build();
        return HttpClients.custom()
                .setConnectionManager(cm)
                .setDefaultRequestConfig(config)
                .disableRedirectHandling()
                .build();
    }

    /**
     * GET through {@link #newSafeApacheClient()}; redirects are followed manually (bounded) and
     * every hop is canonicalized again.
     */
    private static String safeApacheGet(String url) throws IOException {
        URI current = safeUri(url);
        try (CloseableHttpClient client = newSafeApacheClient()) {
            for (int i = 0; i <= MAX_REDIRECTS; i++) {
                try (CloseableHttpResponse response = client.execute(new HttpGet(current))) { // send request
                    int code = response.getStatusLine().getStatusCode();
                    if (isRedirect(code)) {
                        Header location = response.getFirstHeader("Location");
                        current = nextHop(current, location == null ? null : location.getValue());
                        continue;
                    }
                    HttpEntity entity = response.getEntity();
                    return entity == null ? "" : EntityUtils.toString(entity);
                }
            }
        }
        throw new IOException("Too many redirects");
    }


    public static String commonHttpClient(String url) {

        HttpClient client = new HttpClient();
        client.getHttpConnectionManager().getParams().setConnectionTimeout(CONNECT_TIMEOUT_MS);
        client.getHttpConnectionManager().getParams().setSoTimeout(READ_TIMEOUT_MS);

        try {
            URI current = safeUri(url);
            for (int i = 0; i <= MAX_REDIRECTS; i++) {
                // Target is set from components (host config + path + query), no url string is parsed.
                Protocol protocol = Protocol.getProtocol("https".equals(current.getScheme()) ? "https" : "http");
                int port = current.getPort() == -1 ? protocol.getDefaultPort() : current.getPort();
                HostConfiguration hostConfig = new HostConfiguration();
                hostConfig.setHost(current.getHost(), port, protocol);
                GetMethod method = new GetMethod();
                method.setPath(current.getRawPath());
                method.setQueryString(current.getRawQuery());
                method.setFollowRedirects(false);
                try {
                    int code = client.executeMethod(hostConfig, method); // send request
                    if (isRedirect(code)) {
                        org.apache.commons.httpclient.Header location = method.getResponseHeader("Location");
                        current = nextHop(current, location == null ? null : location.getValue());
                        continue;
                    }
                    byte[] resBody = method.getResponseBody();
                    return new String(resBody);
                } finally {
                    // Release the connection.
                    method.releaseConnection();
                }
            }
            return "Error: Too many redirects";
        } catch (IOException e) {
            logger.error("HTTP request failed", e);
            return "Request failed";
        }
    }


    public static String request(String url) {
        try {
            URI current = safeUri(url);
            try (CloseableHttpClient client = newSafeApacheClient()) {
                Executor executor = Executor.newInstance(client);
                for (int i = 0; i <= MAX_REDIRECTS; i++) {
                    HttpResponse response = executor.execute(Request.Get(current)).returnResponse(); // send request
                    int code = response.getStatusLine().getStatusCode();
                    if (isRedirect(code)) {
                        Header location = response.getFirstHeader("Location");
                        current = nextHop(current, location == null ? null : location.getValue());
                        continue;
                    }
                    HttpEntity entity = response.getEntity();
                    return entity == null ? "" : EntityUtils.toString(entity);
                }
            }
            return "Too many redirects";
        } catch (Exception e) {
            logger.error("HTTP request failed", e);
            return "Request failed";
        }
    }


    public static String httpClient(String url) {
        try {
            // The original reader joined the lines without separators; keep that response shape.
            return safeApacheGet(url).replaceAll("\\r?\\n", "");
        } catch (Exception e) {
            logger.error("HTTP request failed", e);
            return "Request failed";
        }
    }


    /**
     * Open a connection to an http(s) url whose host does not resolve to an internal address.
     * Redirects are followed manually (bounded) and every hop is validated again. The connection
     * is opened on the URI rebuilt from validated components, never on the raw string.
     *
     * @param url http request url
     * @return connection whose response headers have already been read
     * @throws IOException if the url (or any redirect target) is not allowed
     */
    public static HttpURLConnection openSafeConnection(String url) throws IOException {
        URI current = safeUri(url);
        for (int i = 0; i <= MAX_REDIRECTS; i++) {
            HttpURLConnection conn = (HttpURLConnection) current.toURL().openConnection();
            conn.setInstanceFollowRedirects(false);
            conn.setConnectTimeout(CONNECT_TIMEOUT_MS);
            conn.setReadTimeout(READ_TIMEOUT_MS);
            int code = conn.getResponseCode();
            if (isRedirect(code)) {
                String location = conn.getHeaderField("Location");
                conn.disconnect();
                current = nextHop(current, location);
                continue;
            }
            return conn;
        }
        throw new IOException("Too many redirects");
    }


    public static String URLConnection(String url) {
        try {
            URLConnection urlConnection = openSafeConnection(url);
            BufferedReader in = new BufferedReader(new InputStreamReader(urlConnection.getInputStream())); //send request
            String inputLine;
            StringBuilder html = new StringBuilder();

            while ((inputLine = in.readLine()) != null) {
                html.append(inputLine);
            }
            in.close();
            return html.toString();
        } catch (Exception e) {
            logger.error("HTTP request failed", e);
            return "Request failed";
        }
    }


    /**
     * The default setting of followRedirects is true.
     * UserAgent is Java/1.8.0_102.
     */
    public static String HttpURLConnection(String url) {
        try {
            HttpURLConnection conn = openSafeConnection(url);
//             Many HttpURLConnection methods can send http request, such as getResponseCode, getHeaderField
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
            logger.error("HTTP request failed", e);
            return "Request failed";
        }
    }


    /**
     * Jsoup is a HTML parser about Java.
     *
     * @param url http request url
     */
    public static String Jsoup(String url) {
        HttpURLConnection conn = null;
        try {
            // Fetch over the validated connection (rebuilt URI, redirects re-validated per hop)
            // and let Jsoup only parse the body.
            conn = openSafeConnection(url);
            String baseUri = conn.getURL().toExternalForm();
            try (InputStream is = conn.getInputStream()) { // send request
                Document doc = Jsoup.parse(is, null, baseUri);
                return doc.outerHtml();
            }
        } catch (IOException e) {
            logger.error("HTTP request failed", e);
            return "Request failed";
        } finally {
            if (conn != null) {
                conn.disconnect();
            }
        }
    }


    /**
     * The default setting of followRedirects is true. The option of followRedirects is true.
     *
     * UserAgent is <code>okhttp/2.5.0</code>.
     */
    public static String okhttp(String url) throws IOException {
        OkHttpClient client = new OkHttpClient();
        // Redirects are followed manually so that every hop is validated again.
        client.setFollowRedirects(false);
        client.setFollowSslRedirects(false);
        client.setConnectTimeout(CONNECT_TIMEOUT_MS, TimeUnit.MILLISECONDS);
        client.setReadTimeout(READ_TIMEOUT_MS, TimeUnit.MILLISECONDS);
        URI current = safeUri(url);
        for (int i = 0; i <= MAX_REDIRECTS; i++) {
            com.squareup.okhttp.Request ok_http = new com.squareup.okhttp.Request.Builder().url(current.toURL()).build();
            com.squareup.okhttp.Response response = client.newCall(ok_http).execute(); // send request
            int code = response.code();
            if (isRedirect(code)) {
                String location = response.header("Location");
                response.body().close();
                current = nextHop(current, location);
                continue;
            }
            return response.body().string();
        }
        throw new IOException("Too many redirects");
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
            // Fetch the body over a validated connection (only remote http(s), rebuilt URI,
            // redirects re-validated per hop), then decode from memory so no user-derived
            // path/URL ever reaches ImageIO.
            ImageIO.setUseCache(false);
            HttpURLConnection conn = openSafeConnection(url); // send request
            byte[] bytes;
            try (InputStream is = conn.getInputStream()) {
                ByteArrayOutputStream out = new ByteArrayOutputStream();
                byte[] buf = new byte[8192];
                int total = 0;
                int n;
                while ((n = is.read(buf)) != -1) {
                    total += n;
                    if (total > MAX_IMAGE_BYTES) {
                        logger.error("Image too large");
                        return;
                    }
                    out.write(buf, 0, n);
                }
                bytes = out.toByteArray();
            } finally {
                conn.disconnect();
            }
            ImageIO.read(new ByteArrayInputStream(bytes));
        } catch (IOException e) {
            logger.error("HTTP request failed", e);
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
            try (InputStream is = openSafeConnection(url).getInputStream()) {
                IOUtils.toByteArray(is);
            }
        } catch (IOException e) {
            logger.error("HTTP request failed", e);
        }
    }


    public static String HttpAsyncClients(String url) {
        final URI safe;
        try {
            safe = safeUri(url);
        } catch (IOException e) {
            logger.error("HTTP request failed", e);
            return "Request failed";
        }
        CloseableHttpAsyncClient httpclient = HttpAsyncClients.createDefault();
        try {
            httpclient.start();
            final HttpGet request = new HttpGet(safe);
            // Do not follow redirects: a redirect target would bypass the check above.
            request.setConfig(RequestConfig.custom().setRedirectsEnabled(false).build());
            Future<HttpResponse> future = httpclient.execute(request, null);
            HttpResponse response = future.get(6000, TimeUnit.MILLISECONDS);
            return EntityUtils.toString(response.getEntity());
        } catch (Exception e) {
            logger.error("HTTP request failed", e);
            return "Request failed";
        } finally {
            try {
                httpclient.close();
            } catch (Exception e) {
                logger.error("HTTP request failed", e);
            }
        }
    }
}
