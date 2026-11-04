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
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.nio.client.CloseableHttpAsyncClient;
import org.apache.http.impl.nio.client.HttpAsyncClients;
import org.apache.http.util.EntityUtils;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.joychou.security.ssrf.SSRFChecker;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.imageio.ImageIO;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.net.URLConnection;
import java.util.concurrent.*;

/**
 * @author JoyChou 2020-04-06
 */
public class HttpUtils {

    private final static Logger logger = LoggerFactory.getLogger(HttpUtils.class);

    private static final String ILLEGAL_URL = "Illegal url";

    /**
     * Outbound url check shared by all request helpers: http/https only and the host must resolve
     * only to public addresses (no loopback, link-local, private, metadata). Callers must also
     * disable automatic redirects so that a redirect cannot reach an internal address.
     * The host is parsed with both {@link URI} and {@link URL} and must be identical, to avoid
     * parser differential bypasses.
     */
    private static boolean isSafeUrl(String url) {
        if (url == null || !SSRFChecker.isSafeOutboundUrl(url)) {
            logger.error("SSRF check failed. Illegal url.");
            return false;
        }
        try {
            String uriHost = new URI(url).getHost();
            String urlHost = new URL(url).getHost();
            return uriHost != null && uriHost.equalsIgnoreCase(urlHost);
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Open a connection to an already validated url without following redirects.
     */
    private static HttpURLConnection openSafeConnection(String url) throws IOException {
        if (!isSafeUrl(url)) {
            throw new IOException(ILLEGAL_URL);
        }
        HttpURLConnection conn = (HttpURLConnection) new URL(url).openConnection();
        conn.setInstanceFollowRedirects(false);
        return conn;
    }


    /**
     * Open an input stream to a remote http(s) url. The host must be public and redirects are not followed.
     *
     * @param url http request url
     * @throws IOException if the url is illegal or the request fails
     */
    public static InputStream openStream(String url) throws IOException {
        return openSafeConnection(url).getInputStream(); // send request
    }


    public static String commonHttpClient(String url) {

        if (!isSafeUrl(url)) {
            return ILLEGAL_URL;
        }

        HttpClient client = new HttpClient();
        GetMethod method = new GetMethod(url);
        method.setFollowRedirects(false);

        try {
            if (!SSRFChecker.isSafeOutboundHost(method.getURI().getHost())) {
                return ILLEGAL_URL;
            }
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
        if (!isSafeUrl(url)) {
            return ILLEGAL_URL;
        }
        try {
            // redirects disabled so that a redirect cannot reach an internal address
            CloseableHttpClient noRedirectClient = HttpClients.custom().disableRedirectHandling().build();
            return Executor.newInstance(noRedirectClient)
                    .execute(Request.Get(url)).returnContent().toString();
        } catch (Exception e) {
            return e.getMessage();
        }
    }


    public static String httpClient(String url) {

        StringBuilder result = new StringBuilder();

        if (!isSafeUrl(url)) {
            return ILLEGAL_URL;
        }

        try {

            CloseableHttpClient client = HttpClients.createDefault();
            HttpGet httpGet = new HttpGet(url);
            // set redirect enable false
            httpGet.setConfig(RequestConfig.custom().setRedirectsEnabled(false).build());
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
            // validated, http/https only, redirects disabled
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
        if (!isSafeUrl(url)) {
            return ILLEGAL_URL;
        }
        try {
            Document doc = Jsoup.connect(url)
                    .followRedirects(false)
                    .timeout(3000)
                    .cookie("name", "joychou") // request cookies
                    .execute().parse();
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
        if (!isSafeUrl(url)) {
            throw new IOException(ILLEGAL_URL);
        }
        OkHttpClient client = new OkHttpClient();
        client.setFollowRedirects(false);
        client.setFollowSslRedirects(false);
        com.squareup.okhttp.Request ok_http = new com.squareup.okhttp.Request.Builder().url(url).build();
        if (!SSRFChecker.isSafeOutboundHost(ok_http.httpUrl().host())) {
            throw new IOException(ILLEGAL_URL);
        }
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
            // Only remote http(s) resources; reject file:, jar:, etc. which read local paths.
            // Host must be public and redirects are not followed.
            HttpURLConnection conn = openSafeConnection(url);
            try (InputStream in = conn.getInputStream()) {
                ImageIO.read(in); // send request
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
            try (InputStream in = conn.getInputStream()) {
                IOUtils.toByteArray(in);
            }
        } catch (IOException e) {
            logger.error(e.getMessage());
        }
    }


    public static String HttpAsyncClients(String url) {
        if (!isSafeUrl(url)) {
            return ILLEGAL_URL;
        }
        CloseableHttpAsyncClient httpclient = HttpAsyncClients.createDefault();
        try {
            httpclient.start();
            final HttpGet request = new HttpGet(url);
            request.setConfig(RequestConfig.custom().setRedirectsEnabled(false).build());
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
