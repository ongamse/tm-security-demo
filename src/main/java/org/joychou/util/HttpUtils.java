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
import org.joychou.security.SecurityUtil;
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
     * Outbound request guard: only http/https and only public destinations
     * (loopback, link-local/metadata, private ranges are rejected). Redirect following is
     * disabled by every caller below so a validated host cannot bounce to an unvalidated one.
     */
    private static boolean isSafeUrl(String url) {
        if (!SecurityUtil.isSafeOutboundUrl(url)) {
            logger.error("Blocked outbound request to illegal url");
            return false;
        }
        return true;
    }

    private static RequestConfig noRedirectConfig() {
        return RequestConfig.custom().setRedirectsEnabled(false).build();
    }

    public static String commonHttpClient(String url) {

        if (!isSafeUrl(url)) {
            return ILLEGAL_URL;
        }
        HttpClient client = new HttpClient();
        GetMethod method = new GetMethod(url);
        method.setFollowRedirects(false);

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
        if (!isSafeUrl(url)) {
            return ILLEGAL_URL;
        }
        try {
            CloseableHttpClient noRedirectClient = HttpClients.custom().disableRedirectHandling().build();
            return Executor.newInstance(noRedirectClient).execute(Request.Get(url)).returnContent().toString();
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
        if (!isSafeUrl(url)) {
            return ILLEGAL_URL;
        }
        try {
            URL u = new URL(url);
            URLConnection urlConnection = u.openConnection();
            if (urlConnection instanceof HttpURLConnection) {
                ((HttpURLConnection) urlConnection).setInstanceFollowRedirects(false);
            }
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
        if (!isSafeUrl(url)) {
            return ILLEGAL_URL;
        }
        try {
            URL u = new URL(url);
            URLConnection urlConnection = u.openConnection();
            HttpURLConnection conn = (HttpURLConnection) urlConnection;
            conn.setInstanceFollowRedirects(false);
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
        // Only remote public http(s) pictures; reject file:, jar: and internal destinations.
        if (!isSafeUrl(url)) {
            return;
        }
        try {
            URL u = new URL(url);
            URLConnection conn = u.openConnection();
            if (conn instanceof HttpURLConnection) {
                ((HttpURLConnection) conn).setInstanceFollowRedirects(false);
            }
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
        if (!isSafeUrl(url)) {
            return;
        }
        try {
            URLConnection conn = URI.create(url).toURL().openConnection();
            if (conn instanceof HttpURLConnection) {
                ((HttpURLConnection) conn).setInstanceFollowRedirects(false);
            }
            IOUtils.toByteArray(conn);
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
            request.setConfig(noRedirectConfig());
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
