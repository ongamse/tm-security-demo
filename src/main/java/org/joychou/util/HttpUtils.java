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
import org.joychou.security.ssrf.SSRFChecker;
import org.joychou.security.SecurityUtil;
import org.joychou.security.ssrf.SSRFException;
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
import java.net.URI;
import java.util.concurrent.*;

/**
 * Every method validates the destination with {@link SSRFChecker#requireSafeUri(String)}
 * (http/https only, no loopback/link-local/private/metadata address after DNS resolution)
 * and does not follow redirects automatically, because a redirect could point to an internal host.
 *
 * @author JoyChou 2020-04-06
 */
public class HttpUtils {

    private final static Logger logger = LoggerFactory.getLogger(HttpUtils.class);

    /**
     * Log the exception server side and return a constant message so that
     * exception details are never returned to the caller / HTTP response.
     */
    private static String requestFailed(Exception e) {
        logger.error(SecurityUtil.logSafe(e.toString()));
        return "Request failed";
    }

    /**
     * Open a validated http/https URI without following redirects.
     */
    private static HttpURLConnection openNoRedirect(URI uri) throws IOException {
        HttpURLConnection conn = (HttpURLConnection) uri.toURL().openConnection();
        conn.setInstanceFollowRedirects(false);
        return conn;
    }


    /**
     * Open an input stream of a validated http/https url without following redirects.
     *
     * @param url untrusted http request url
     * @throws SSRFException if the url targets a non http/https scheme or an internal address
     */
    public static InputStream openStream(String url) throws IOException {
        URI uri = SSRFChecker.requireSafeUri(url);
        return openNoRedirect(uri).getInputStream(); // send request
    }


    public static String commonHttpClient(String url) {

        HttpClient client = new HttpClient();
        GetMethod method = null;

        try {
            method = new GetMethod(SSRFChecker.requireSafeUri(url).toString());
            method.setFollowRedirects(false);
            client.executeMethod(method); // send request
            byte[] resBody = method.getResponseBody();
            return new String(resBody);

        } catch (SSRFException | IOException e) {
            return requestFailed(e);
        } finally {
            // Release the connection.
            if (method != null) {
                method.releaseConnection();
            }
        }
    }


    public static String request(String url) {
        try (CloseableHttpClient client = HttpClients.custom().disableRedirectHandling().build()) {
            HttpGet httpGet = new HttpGet(SSRFChecker.requireSafeUri(url));
            HttpResponse httpResponse = client.execute(httpGet); // send request
            return EntityUtils.toString(httpResponse.getEntity());
        } catch (Exception e) {
            return requestFailed(e);
        }
    }


    public static String httpClient(String url) {

        StringBuilder result = new StringBuilder();

        try {

            CloseableHttpClient client = HttpClients.createDefault();
            HttpGet httpGet = new HttpGet(SSRFChecker.requireSafeUri(url));
            // redirects are disabled so that a redirect cannot reach an internal address
            httpGet.setConfig(RequestConfig.custom().setRedirectsEnabled(false).build());
            HttpResponse httpResponse = client.execute(httpGet); // send request
            BufferedReader rd = new BufferedReader(new InputStreamReader(httpResponse.getEntity().getContent()));

            String line;
            while ((line = rd.readLine()) != null) {
                result.append(line);
            }

            return result.toString();

        } catch (Exception e) {
            return requestFailed(e);
        }
    }


    public static String URLConnection(String url) {
        try {
            URI u = SSRFChecker.requireSafeUri(url);
            HttpURLConnection urlConnection = openNoRedirect(u);
            BufferedReader in = new BufferedReader(new InputStreamReader(urlConnection.getInputStream())); //send request
            String inputLine;
            StringBuilder html = new StringBuilder();

            while ((inputLine = in.readLine()) != null) {
                html.append(inputLine);
            }
            in.close();
            return html.toString();
        } catch (Exception e) {
            return requestFailed(e);
        }
    }


    /**
     * Redirects are not followed. UserAgent is Java/1.8.0_102.
     */
    public static String HttpURLConnection(String url) {
        try {
            URI u = SSRFChecker.requireSafeUri(url);
            HttpURLConnection conn = openNoRedirect(u);
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
        } catch (SSRFException | IOException e) {
            return requestFailed(e);
        }
    }


    /**
     * Jsoup is a HTML parser about Java.
     *
     * @param url http request url
     */
    public static String Jsoup(String url) {
        try {
            Document doc = Jsoup.connect(SSRFChecker.requireSafeUri(url).toString())
                    .followRedirects(false)
                    .timeout(3000)
                    .cookie("name", "joychou") // request cookies
                    .execute().parse();
            return doc.outerHtml();
        } catch (SSRFException | IOException e) {
            return requestFailed(e);
        }
    }


    /**
     * Redirects are not followed.
     *
     * UserAgent is <code>okhttp/2.5.0</code>.
     */
    public static String okhttp(String url) throws IOException {
        URI uri = SSRFChecker.requireSafeUri(url);
        OkHttpClient client = new OkHttpClient();
        client.setFollowRedirects(false);
        client.setFollowSslRedirects(false);
        com.squareup.okhttp.Request ok_http = new com.squareup.okhttp.Request.Builder().url(uri.toURL()).build();
        return client.newCall(ok_http).execute().body().string();
    }


    /**
     * Redirects are not followed.
     *
     * UserAgent is Java/1.8.0_102.
     *
     * @param url http request url
     */
    public static void imageIO(String url) {
        try (InputStream is = openStream(url)) {
            ImageIO.read(is); // send request
        } catch (IOException e) {
            logger.error(e.getMessage());
        }

    }


    /**
     * IOUtils which is wrapped by URLConnection can get remote pictures.
     * Redirects are not followed.
     *
     * @param url http request url
     */
    public static void IOUtils(String url) {
        try (InputStream is = openStream(url)) {
            IOUtils.toByteArray(is);
        } catch (IOException e) {
            logger.error(e.getMessage());
        }
    }


    public static String HttpAsyncClients(String url) {
        CloseableHttpAsyncClient httpclient = HttpAsyncClients.custom()
                .setDefaultRequestConfig(RequestConfig.custom().setRedirectsEnabled(false).build())
                .build();
        try {
            final HttpGet request = new HttpGet(SSRFChecker.requireSafeUri(url));
            httpclient.start();
            Future<HttpResponse> future = httpclient.execute(request, null);
            HttpResponse response = future.get(6000, TimeUnit.MILLISECONDS);
            return EntityUtils.toString(response.getEntity());
        } catch (Exception e) {
            return requestFailed(e);
        } finally {
            try {
                httpclient.close();
            } catch (Exception e) {
                logger.error(e.getMessage());
            }
        }
    }
}
