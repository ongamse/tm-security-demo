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
import org.joychou.security.SecurityUtil;
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
import java.net.URL;
import java.net.URLConnection;
import java.util.concurrent.*;

/**
 * @author JoyChou 2020-04-06
 */
public class HttpUtils {

    private final static Logger logger = LoggerFactory.getLogger(HttpUtils.class);

    /**
     * Validate an untrusted url before any outbound request: only http/https and the
     * destination must not resolve to an internal / blocked address
     * ({@link SecurityUtil#checkSSRFWithoutRedirect(String)}). Callers must not follow
     * redirects automatically, otherwise a redirect could reach an unchecked host.
     *
     * @param url untrusted url
     * @return the validated url
     * @throws IOException if the url is not allowed
     */
    private static String checkedUrl(String url) throws IOException {
        // request the url rebuilt from validated components, so the checked host is the fetched host
        String safeUrl = SecurityUtil.canonicalHttpUrl(url);
        if (safeUrl == null || !SecurityUtil.checkSSRFWithoutRedirect(safeUrl)) {
            throw new IOException("[-] SSRF check failed");
        }
        return safeUrl;
    }


    /**
     * Open a validated http(s) connection which does not follow redirects.
     *
     * @param url untrusted url
     */
    private static HttpURLConnection openChecked(String url) throws IOException {
        URLConnection urlConnection = new URL(checkedUrl(url)).openConnection();
        if (!(urlConnection instanceof HttpURLConnection)) {
            throw new IOException("[-] SSRF check failed");
        }
        HttpURLConnection conn = (HttpURLConnection) urlConnection;
        conn.setInstanceFollowRedirects(false);
        return conn;
    }


    /**
     * Open an input stream for a validated http(s) url (no redirects).
     *
     * @param url untrusted url
     */
    public static InputStream openStream(String url) throws IOException {
        return openChecked(url).getInputStream();
    }


    public static String commonHttpClient(String url) {

        HttpClient client = new HttpClient();
        GetMethod method = null;

        try {
            method = new GetMethod(checkedUrl(url));
            method.setFollowRedirects(false);
            client.executeMethod(method); // send request
            byte[] resBody = method.getResponseBody();
            return new String(resBody);

        } catch (IOException e) {
            return "Error: " + e.getMessage();
        } finally {
            // Release the connection.
            if (method != null) {
                method.releaseConnection();
            }
        }
    }


    public static String request(String url) {
        try {
            String safeUrl = checkedUrl(url);
            Executor executor = Executor.newInstance(HttpClients.custom().disableRedirectHandling().build());
            return executor.execute(Request.Get(safeUrl)).returnContent().toString();
        } catch (Exception e) {
            return e.getMessage();
        }
    }


    public static String httpClient(String url) {

        StringBuilder result = new StringBuilder();

        try {

            CloseableHttpClient client = HttpClients.custom().disableRedirectHandling().build();
            HttpGet httpGet = new HttpGet(checkedUrl(url));
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
            HttpURLConnection urlConnection = openChecked(url);
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
            HttpURLConnection conn = openChecked(url);
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
            Document doc = Jsoup.connect(checkedUrl(url))
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
        OkHttpClient client = new OkHttpClient();
        client.setFollowRedirects(false);
        client.setFollowSslRedirects(false);
        com.squareup.okhttp.Request ok_http = new com.squareup.okhttp.Request.Builder().url(checkedUrl(url)).build();
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
            try (InputStream is = openStream(url)) {
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
            try (InputStream is = openStream(url)) {
                IOUtils.toByteArray(is);
            }
        } catch (IOException e) {
            logger.error(e.getMessage());
        }
    }


    public static String HttpAsyncClients(String url) {
        CloseableHttpAsyncClient httpclient = HttpAsyncClients.custom()
                .setDefaultRequestConfig(RequestConfig.custom().setRedirectsEnabled(false).build())
                .build();
        try {
            final HttpGet request = new HttpGet(checkedUrl(url));
            httpclient.start();
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
