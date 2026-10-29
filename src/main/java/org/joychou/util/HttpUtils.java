package org.joychou.util;

import com.squareup.okhttp.OkHttpClient;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.methods.GetMethod;
import org.apache.commons.io.IOUtils;
import org.apache.http.HttpResponse;
import org.apache.http.HttpRequest;
import org.apache.http.ProtocolException;
import org.apache.http.client.fluent.Executor;
import org.apache.http.client.fluent.Request;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.config.Registry;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.conn.DnsResolver;
import org.apache.http.conn.socket.ConnectionSocketFactory;
import org.apache.http.conn.socket.PlainConnectionSocketFactory;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.DefaultRedirectStrategy;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;
import org.apache.http.protocol.HttpContext;
import org.apache.http.impl.nio.client.CloseableHttpAsyncClient;
import org.apache.http.impl.nio.client.HttpAsyncClients;
import org.apache.http.util.EntityUtils;
import org.joychou.security.ssrf.SafeUrl;
import org.jsoup.Connection;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.imageio.ImageIO;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.concurrent.*;

/**
 * @author JoyChou 2020-04-06
 */
public class HttpUtils {

    private final static Logger logger = LoggerFactory.getLogger(HttpUtils.class);

    private static final int MAX_REDIRECTS = 5;
    private static final int TIMEOUT_MS = 10 * 1000;

    private static boolean isRedirect(int code) {
        return code == 301 || code == 302 || code == 303 || code == 307 || code == 308;
    }


    /**
     * Open a connection to the url. Every redirect hop is validated before it is requested.
     */
    private static HttpURLConnection openSafeConnection(String url) throws IOException {
        SafeUrl current = SafeUrl.parse(url);
        for (int i = 0; i <= MAX_REDIRECTS; i++) {
            // The request url is rebuilt from the validated components, not taken from the raw string.
            HttpURLConnection conn = (HttpURLConnection) current.toURL().openConnection();
            conn.setInstanceFollowRedirects(false);
            conn.setConnectTimeout(TIMEOUT_MS);
            conn.setReadTimeout(TIMEOUT_MS);
            int code = conn.getResponseCode(); // send request
            if (!isRedirect(code)) {
                return conn;
            }
            String location = conn.getHeaderField("Location");
            conn.disconnect();
            current = current.resolve(location);
        }
        throw new IOException("Too many redirects");
    }


    /**
     * Resolve every address of the host and refuse internal ones at connect time,
     * so the checked address is the connected address (no DNS rebinding) for every redirect hop.
     */
    private static class SafeDnsResolver implements DnsResolver {
        @Override
        public InetAddress[] resolve(String host) throws UnknownHostException {
            try {
                return SafeUrl.resolveExternal(host);
            } catch (IOException e) {
                throw new UnknownHostException(e.getMessage());
            }
        }
    }


    /**
     * Validate every redirect target of the Apache http clients.
     */
    private static class SafeRedirectStrategy extends DefaultRedirectStrategy {
        @Override
        public HttpUriRequest getRedirect(HttpRequest request, org.apache.http.HttpResponse response,
                                          HttpContext context) throws ProtocolException {
            HttpUriRequest redirect = super.getRedirect(request, response, context);
            try {
                SafeUrl.parse(redirect.getURI().toString());
            } catch (IOException e) {
                throw new ProtocolException(e.getMessage());
            }
            return redirect;
        }
    }


    private static CloseableHttpClient safeHttpClient() {
        Registry<ConnectionSocketFactory> registry = RegistryBuilder.<ConnectionSocketFactory>create()
                .register("http", PlainConnectionSocketFactory.getSocketFactory())
                .register("https", SSLConnectionSocketFactory.getSocketFactory())
                .build();
        PoolingHttpClientConnectionManager cm = new PoolingHttpClientConnectionManager(registry, new SafeDnsResolver());
        return HttpClients.custom()
                .setConnectionManager(cm)
                .setRedirectStrategy(new SafeRedirectStrategy())
                .build();
    }

    /**
     * Open a stream of a remote http(s) url. The scheme and host (including every redirect hop)
     * are validated; internal / loopback / link-local addresses are refused.
     */
    public static InputStream openStream(String url) throws IOException {
        return openSafeConnection(url).getInputStream();
    }


    public static String commonHttpClient(String url) {

        HttpClient client = new HttpClient();

        try {
            GetMethod method = new GetMethod(SafeUrl.parse(url).toExternalForm());
            // Do not follow redirects, so a validated url cannot be redirected to an internal one.
            method.setFollowRedirects(false);
            return executeSafely(client, method);
        } catch (IOException e) {
            return "Error: " + e.getMessage();
        }
    }


    private static String executeSafely(HttpClient client, GetMethod method) {
        try {
            client.executeMethod(method); // send request
            byte[] resBody = method.getResponseBody();
            return new String(resBody);

        } catch (IOException e) {
            return "Error: " + e.getMessage();
        } finally {
            // Release the connection.
            method.releaseConnection();
        }
    }


    public static String request(String url) {
        try {
            String safeUrl = SafeUrl.parse(url).toExternalForm();
            try (CloseableHttpClient client = safeHttpClient()) {
                return Executor.newInstance(client).execute(Request.Get(safeUrl)).returnContent().toString();
            }
        } catch (Exception e) {
            return e.getMessage();
        }
    }


    public static String httpClient(String url) {

        StringBuilder result = new StringBuilder();

        try {

            String safeUrl = SafeUrl.parse(url).toExternalForm();
            try (CloseableHttpClient client = safeHttpClient()) {
                HttpGet httpGet = new HttpGet(safeUrl);
                HttpResponse httpResponse = client.execute(httpGet); // send request
                BufferedReader rd = new BufferedReader(new InputStreamReader(httpResponse.getEntity().getContent()));

                String line;
                while ((line = rd.readLine()) != null) {
                    result.append(line);
                }
            }

            return result.toString();

        } catch (Exception e) {
            return e.getMessage();
        }
    }


    public static String URLConnection(String url) {
        try {
            HttpURLConnection urlConnection = openSafeConnection(url);
            BufferedReader in = new BufferedReader(new InputStreamReader(urlConnection.getInputStream())); //send request
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
            SafeUrl current = SafeUrl.parse(url);
            for (int i = 0; i <= MAX_REDIRECTS; i++) {
                Connection.Response res = Jsoup.connect(current.toExternalForm())
                        .followRedirects(false) // every redirect hop is validated below
                        .timeout(3000)
                        .cookie("name", "joychou") // request cookies
                        .execute();
                if (isRedirect(res.statusCode())) {
                    current = current.resolve(res.header("Location"));
                    continue;
                }
                Document doc = res.parse();
                return doc.outerHtml();
            }
            return "Too many redirects";
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
        OkHttpClient client = new OkHttpClient();
        client.setFollowRedirects(false); // every redirect hop is validated below
        SafeUrl current = SafeUrl.parse(url);
        for (int i = 0; i <= MAX_REDIRECTS; i++) {
            com.squareup.okhttp.Request ok_http = new com.squareup.okhttp.Request.Builder().url(current.toURL()).build();
            com.squareup.okhttp.Response response = client.newCall(ok_http).execute();
            if (isRedirect(response.code())) {
                String location = response.header("Location");
                response.body().close();
                current = current.resolve(location);
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
            // Only remote http(s) pictures with a non-internal host; reject file:, jar:, etc.
            // Redirects are followed manually and every hop is validated.
            HttpURLConnection conn = openSafeConnection(url);
            try (InputStream is = conn.getInputStream()) {
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
            HttpURLConnection conn = openSafeConnection(url);
            try (InputStream is = conn.getInputStream()) {
                IOUtils.toByteArray(is);
            }
        } catch (IOException e) {
            logger.error(e.getMessage());
        }
    }


    public static String HttpAsyncClients(String url) {
        CloseableHttpAsyncClient httpclient = HttpAsyncClients.custom()
                .setRedirectStrategy(new SafeRedirectStrategy())
                .build();
        try {
            String safeUrl = SafeUrl.parse(url).toExternalForm();
            httpclient.start();
            final HttpGet request = new HttpGet(safeUrl);
            Future<HttpResponse> future = httpclient.execute(request, null);
            HttpResponse response = future.get(6000, TimeUnit.MILLISECONDS);
            return EntityUtils.toString(response.getEntity());
        } catch (Exception e) {
            return e.getMessage();
        } finally {
            try {
                httpclient.close();
            } catch (Exception e) {
                logger.error(e.getMessage());
            }
        }
    }
}
