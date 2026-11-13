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
import org.apache.http.impl.client.HttpClientBuilder;
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
import java.net.URL;
import java.net.URLConnection;
import java.util.concurrent.*;

/**
 * @author JoyChou 2020-04-06
 */
public class HttpUtils {

    private final static Logger logger = LoggerFactory.getLogger(HttpUtils.class);

    private static final int TIMEOUT_MS = 5000;

    private static final RequestConfig SAFE_CONFIG = RequestConfig.custom().setRedirectsEnabled(false)
            .setConnectTimeout(TIMEOUT_MS).setSocketTimeout(TIMEOUT_MS)
            .setConnectionRequestTimeout(TIMEOUT_MS).build();

    /**
     * Validate the url with {@link SecurityUtil#requireSafeUrl(String)} and open a connection that does
     * not follow redirects. The connection is opened on the rebuilt, validated url only.
     *
     * @param url the url that is about to be requested
     * @return unconnected http connection
     * @throws IOException if the url is not allowed
     */
    public static HttpURLConnection openSafeConnection(String url) throws IOException {
        URL safe = SecurityUtil.requireSafeUrl(url);
        HttpURLConnection conn = (HttpURLConnection) safe.openConnection();
        conn.setInstanceFollowRedirects(false);
        conn.setConnectTimeout(TIMEOUT_MS);
        conn.setReadTimeout(TIMEOUT_MS);
        return conn;
    }

    public static String commonHttpClient(String url) {

        HttpClient client = new HttpClient();
        client.getHttpConnectionManager().getParams().setConnectionTimeout(TIMEOUT_MS);
        client.getHttpConnectionManager().getParams().setSoTimeout(TIMEOUT_MS);

        try {
            URL safe = SecurityUtil.requireSafeUrl(url);
            GetMethod method = new GetMethod(safe.toExternalForm());
            method.setFollowRedirects(false);
            return executeCommonHttpClient(client, method);
        } catch (IOException e) {
            return "Error: " + e.getMessage();
        }
    }

    private static String executeCommonHttpClient(HttpClient client, GetMethod method) {
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
            URL safe = SecurityUtil.requireSafeUrl(url);
            Executor executor = Executor.newInstance(HttpClientBuilder.create().disableRedirectHandling().build());
            return executor.execute(Request.Get(safe.toURI())
                    .connectTimeout(TIMEOUT_MS).socketTimeout(TIMEOUT_MS)).returnContent().toString();
        } catch (Exception e) {
            return e.getMessage();
        }
    }


    public static String httpClient(String url) {

        StringBuilder result = new StringBuilder();

        try {

            URL safe = SecurityUtil.requireSafeUrl(url);
            CloseableHttpClient client = HttpClients.createDefault();
            HttpGet httpGet = new HttpGet(safe.toURI());
            // set redirect enable false
            httpGet.setConfig(SAFE_CONFIG);
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
            URL safe = SecurityUtil.requireSafeUrl(url);
            Document doc = Jsoup.connect(safe.toExternalForm())
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
        URL safe = SecurityUtil.requireSafeUrl(url);
        OkHttpClient client = new OkHttpClient();
        client.setFollowRedirects(false);
        client.setFollowSslRedirects(false);
        client.setConnectTimeout(TIMEOUT_MS, TimeUnit.MILLISECONDS);
        client.setReadTimeout(TIMEOUT_MS, TimeUnit.MILLISECONDS);
        com.squareup.okhttp.Request ok_http = new com.squareup.okhttp.Request.Builder().url(safe).build();
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
                IOUtils.toByteArray(is); // send request
            }
        } catch (IOException e) {
            logger.error(e.getMessage());
        }
    }


    public static String HttpAsyncClients(String url) {
        CloseableHttpAsyncClient httpclient = HttpAsyncClients.createDefault();
        try {
            httpclient.start();
            URL safe = SecurityUtil.requireSafeUrl(url);
            final HttpGet request = new HttpGet(safe.toURI());
            request.setConfig(SAFE_CONFIG);
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
