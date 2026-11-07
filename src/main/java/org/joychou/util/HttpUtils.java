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
import java.net.URL;
import java.net.URLConnection;
import java.util.concurrent.*;

/**
 * @author JoyChou 2020-04-06
 */
public class HttpUtils {

    private final static Logger logger = LoggerFactory.getLogger(HttpUtils.class);

    private static final String ILLEGAL_URL = "[-] SSRF check failed. Illegal url.";

    private static final int CONNECT_TIMEOUT_MS = 3000;
    private static final int READ_TIMEOUT_MS = 6000;

    /**
     * Every method below resolves the user supplied url exactly once through
     * {@link SecurityUtil#resolveAllowedUrl(String)}. That url is rebuilt from a constant scheme, an
     * exactly matched server side allowlisted host and a validated path, and only the rebuilt value
     * reaches a client. Redirects are disabled and timeouts are set on every client, so that an
     * allowlisted url can not bounce the request to an internal one.
     */
    private static URL resolve(String rawUrl) {
        URL allowed = SecurityUtil.resolveAllowedUrl(rawUrl);
        if (allowed == null) {
            logger.error("Illegal outbound url rejected");
        }
        return allowed;
    }

    /**
     * Open a connection to an already resolved url without following redirects.
     */
    private static HttpURLConnection openSafeConnection(URL allowed) throws IOException {
        HttpURLConnection conn = (HttpURLConnection) allowed.openConnection();
        conn.setInstanceFollowRedirects(false);
        conn.setConnectTimeout(CONNECT_TIMEOUT_MS);
        conn.setReadTimeout(READ_TIMEOUT_MS);
        return conn;
    }

    private static RequestConfig safeRequestConfig() {
        return RequestConfig.custom()
                .setRedirectsEnabled(false)
                .setConnectTimeout(CONNECT_TIMEOUT_MS)
                .setSocketTimeout(READ_TIMEOUT_MS)
                .build();
    }

    public static String commonHttpClient(String url) {

        URL allowed = resolve(url);
        if (allowed == null) {
            return ILLEGAL_URL;
        }

        HttpClient client = new HttpClient();
        client.getHttpConnectionManager().getParams().setConnectionTimeout(CONNECT_TIMEOUT_MS);
        client.getHttpConnectionManager().getParams().setSoTimeout(READ_TIMEOUT_MS);
        GetMethod method = new GetMethod(allowed.toExternalForm());
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
        URL allowed = resolve(url);
        if (allowed == null) {
            return ILLEGAL_URL;
        }
        try {
            Executor executor = Executor.newInstance(HttpClients.custom().disableRedirectHandling().build());
            return executor.execute(Request.Get(allowed.toURI())
                    .connectTimeout(CONNECT_TIMEOUT_MS)
                    .socketTimeout(READ_TIMEOUT_MS)).returnContent().toString();
        } catch (Exception e) {
            return e.getMessage();
        }
    }


    public static String httpClient(String url) {

        URL allowed = resolve(url);
        if (allowed == null) {
            return ILLEGAL_URL;
        }

        StringBuilder result = new StringBuilder();

        try {

            CloseableHttpClient client = HttpClients.custom().disableRedirectHandling().build();
            HttpGet httpGet = new HttpGet(allowed.toURI());
            // redirects disabled, connect and read timeouts set
            httpGet.setConfig(safeRequestConfig());
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
        URL allowed = resolve(url);
        if (allowed == null) {
            return ILLEGAL_URL;
        }
        try {
            URLConnection urlConnection = openSafeConnection(allowed);
            BufferedReader in = new BufferedReader(new InputStreamReader(urlConnection.getInputStream())); //send request
            String inputLine;
            StringBuilder html = new StringBuilder();

            while ((inputLine = in.readLine()) != null) {
                html.append(inputLine);
            }
            in.close();
            return html.toString();
        } catch (Exception e) {
            logger.error("Outbound request failed: {}", e.getClass().getSimpleName());
            return e.getMessage();
        }
    }


    /**
     * The default setting of followRedirects is true.
     * UserAgent is Java/1.8.0_102.
     */
    public static String HttpURLConnection(String url) {
        URL allowed = resolve(url);
        if (allowed == null) {
            return ILLEGAL_URL;
        }
        try {
            HttpURLConnection conn = openSafeConnection(allowed);
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
            logger.error("Outbound request failed: {}", e.getClass().getSimpleName());
            return e.getMessage();
        }
    }


    /**
     * Jsoup is a HTML parser about Java.
     *
     * @param url http request url
     */
    public static String Jsoup(String url) {
        URL allowed = resolve(url);
        if (allowed == null) {
            return ILLEGAL_URL;
        }
        try {
            Document doc = Jsoup.connect(allowed.toExternalForm())
                    .followRedirects(false)
                    .timeout(READ_TIMEOUT_MS)
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
        URL allowed = resolve(url);
        if (allowed == null) {
            return ILLEGAL_URL;
        }
        OkHttpClient client = new OkHttpClient();
        client.setFollowRedirects(false);
        client.setFollowSslRedirects(false);
        client.setConnectTimeout(CONNECT_TIMEOUT_MS, TimeUnit.MILLISECONDS);
        client.setReadTimeout(READ_TIMEOUT_MS, TimeUnit.MILLISECONDS);
        com.squareup.okhttp.Request ok_http = new com.squareup.okhttp.Request.Builder().url(allowed).build();
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
            // http/https only (rejects file:, jar:, etc.), allowlisted hosts only
            URL allowed = resolve(url);
            if (allowed == null) {
                return;
            }
            HttpURLConnection conn = openSafeConnection(allowed);
            try (InputStream in = conn.getInputStream()) { // send request
                ImageIO.read(in);
            }
        } catch (IOException e) {
            logger.error("Outbound request failed: {}", e.getClass().getSimpleName());
        }

    }


    /**
     * IOUtils which is wrapped by URLConnection can get remote pictures.
     * The default setting of redirection is true.
     *
     * @param url http request url
     */
    public static void IOUtils(String url) {
        URL allowed = resolve(url);
        if (allowed == null) {
            return;
        }
        try {
            IOUtils.toByteArray(openSafeConnection(allowed));
        } catch (IOException e) {
            logger.error("Outbound request failed: {}", e.getClass().getSimpleName());
        }
    }


    public static String HttpAsyncClients(String url) {
        URL allowed = resolve(url);
        if (allowed == null) {
            return ILLEGAL_URL;
        }
        CloseableHttpAsyncClient httpclient = HttpAsyncClients.custom()
                .setDefaultRequestConfig(safeRequestConfig())
                .build();
        try {
            httpclient.start();
            final HttpGet request = new HttpGet(allowed.toURI());
            Future<HttpResponse> future = httpclient.execute(request, null);
            HttpResponse response = future.get(READ_TIMEOUT_MS, TimeUnit.MILLISECONDS);
            return EntityUtils.toString(response.getEntity());
        } catch (Exception e) {
            return e.getMessage();
        } finally {
            try {
                httpclient.close();
            } catch (Exception e) {
                logger.error("Outbound request failed: {}", e.getClass().getSimpleName());
            }
        }
    }
}
