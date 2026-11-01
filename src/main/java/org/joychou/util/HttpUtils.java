package org.joychou.util;

import com.squareup.okhttp.OkHttpClient;
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
import org.joychou.security.ssrf.SSRFChecker;
import org.joychou.security.ssrf.SSRFException;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.imageio.ImageIO;
import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.*;

/**
 * Outgoing HTTP helpers. Every helper validates the url with {@link SSRFChecker#validateHttpUrl(String)}
 * (http/https only, no user info, host must resolve only to public addresses) and does not
 * follow redirects automatically. Helpers that need redirects follow them manually and validate every hop.
 *
 * @author JoyChou 2020-04-06
 */
public class HttpUtils {

    private final static Logger logger = LoggerFactory.getLogger(HttpUtils.class);

    private static final String REQUEST_FAILED = "Request failed";
    private static final int MAX_REDIRECTS = 5;
    private static final int CONNECT_TIMEOUT_MS = 5000;
    private static final int READ_TIMEOUT_MS = 10000;
    private static final int MAX_BODY_BYTES = 1024 * 1024;

    /**
     * Open a connection to a validated url. Redirects are followed manually and each hop is validated again.
     * The returned connection already has its response code fetched and is not a redirect.
     */
    private static HttpURLConnection openValidatedConnection(String url) throws IOException {
        String current = url;
        for (int i = 0; i <= MAX_REDIRECTS; i++) {
            URI uri = SSRFChecker.validateHttpUrl(current);
            HttpURLConnection conn = (HttpURLConnection) uri.toURL().openConnection();
            conn.setInstanceFollowRedirects(false);
            conn.setConnectTimeout(CONNECT_TIMEOUT_MS);
            conn.setReadTimeout(READ_TIMEOUT_MS);
            int code = conn.getResponseCode(); // send request
            if (code == 301 || code == 302 || code == 303 || code == 307 || code == 308) {
                String location = conn.getHeaderField("Location");
                conn.disconnect();
                if (location == null) {
                    throw new IOException("Redirect without Location header");
                }
                try {
                    current = uri.resolve(location).toString();
                } catch (IllegalArgumentException e) {
                    throw new SSRFException("[-] SSRF check failed. Illegal redirect url.");
                }
                continue;
            }
            return conn;
        }
        throw new IOException("Too many redirects");
    }


    /**
     * Open an input stream for a validated http/https url. Redirects are followed manually and validated.
     *
     * @param url http request url
     * @return response body stream; the caller must close it
     * @throws IOException   on connection failure
     * @throws SSRFException if the url (or any redirect hop) is not allowed
     */
    public static InputStream openStream(String url) throws IOException {
        return openValidatedConnection(url).getInputStream();
    }


    /**
     * Read at most {@link #MAX_BODY_BYTES} bytes from the stream.
     */
    private static byte[] readBounded(InputStream in) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buf = new byte[4096];
        int total = 0;
        int n;
        while (total < MAX_BODY_BYTES && (n = in.read(buf, 0, Math.min(buf.length, MAX_BODY_BYTES - total))) != -1) {
            out.write(buf, 0, n);
            total += n;
        }
        return out.toByteArray();
    }


    public static String commonHttpClient(String url) {
        try {
            HttpURLConnection conn = openValidatedConnection(url); // send request
            try (InputStream in = conn.getInputStream()) {
                return new String(readBounded(in), StandardCharsets.UTF_8);
            } finally {
                conn.disconnect();
            }
        } catch (IOException | SSRFException e) {
            logger.error("commonHttpClient failed: {}", e.getClass().getSimpleName());
            return REQUEST_FAILED;
        }
    }


    public static String request(String url) {
        try {
            URI uri = SSRFChecker.validateHttpUrl(url);
            CloseableHttpClient client = HttpClients.custom().disableRedirectHandling().build();
            try {
                return Executor.newInstance(client).execute(Request.Get(uri)).returnContent().toString();
            } finally {
                client.close();
            }
        } catch (Exception e) {
            logger.error("request failed: {}", e.getClass().getSimpleName());
            return REQUEST_FAILED;
        }
    }


    public static String httpClient(String url) {

        StringBuilder result = new StringBuilder();

        try {
            URI uri = SSRFChecker.validateHttpUrl(url);
            CloseableHttpClient client = HttpClients.custom().disableRedirectHandling().build();
            HttpGet httpGet = new HttpGet(uri);
            HttpResponse httpResponse = client.execute(httpGet); // send request
            BufferedReader rd = new BufferedReader(new InputStreamReader(httpResponse.getEntity().getContent()));

            String line;
            while ((line = rd.readLine()) != null) {
                result.append(line);
            }

            return result.toString();

        } catch (Exception e) {
            logger.error("httpClient failed: {}", e.getClass().getSimpleName());
            return REQUEST_FAILED;
        }
    }


    public static String URLConnection(String url) {
        try {
            HttpURLConnection urlConnection = openValidatedConnection(url); //send request
            BufferedReader in = new BufferedReader(new InputStreamReader(urlConnection.getInputStream()));
            String inputLine;
            StringBuilder html = new StringBuilder();

            while ((inputLine = in.readLine()) != null) {
                html.append(inputLine);
            }
            in.close();
            return html.toString();
        } catch (Exception e) {
            logger.error("URLConnection failed: {}", e.getClass().getSimpleName());
            return REQUEST_FAILED;
        }
    }


    /**
     * Only http/https urls to public hosts are requested. Redirects are followed manually and validated.
     */
    public static String HttpURLConnection(String url) {
        try {
            HttpURLConnection conn = openValidatedConnection(url);
//             Many HttpURLConnection methods can send http request, such as getResponseCode, getHeaderField
            InputStream is = conn.getInputStream();
            BufferedReader in = new BufferedReader(new InputStreamReader(is));
            String inputLine;
            StringBuilder html = new StringBuilder();

            while ((inputLine = in.readLine()) != null) {
                html.append(inputLine);
            }
            in.close();
            return html.toString();
        } catch (IOException | SSRFException e) {
            logger.error("HttpURLConnection failed: {}", e.getClass().getSimpleName());
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
            HttpURLConnection conn = openValidatedConnection(url); // send request
            try (InputStream in = conn.getInputStream()) {
                Document doc = Jsoup.parse(in, "UTF-8", conn.getURL().toString());
                return doc.outerHtml();
            } finally {
                conn.disconnect();
            }
        } catch (IOException | SSRFException e) {
            logger.error("Jsoup failed: {}", e.getClass().getSimpleName());
            return REQUEST_FAILED;
        }
    }


    /**
     * Redirects are not followed.
     *
     * UserAgent is <code>okhttp/2.5.0</code>.
     */
    public static String okhttp(String url) throws IOException {
        URI uri = SSRFChecker.validateHttpUrl(url);
        OkHttpClient client = new OkHttpClient();
        client.setFollowRedirects(false);
        client.setFollowSslRedirects(false);
        com.squareup.okhttp.Request ok_http = new com.squareup.okhttp.Request.Builder().url(uri.toURL()).build();
        return client.newCall(ok_http).execute().body().string();
    }


    /**
     * Redirects are followed manually and validated.
     *
     * UserAgent is Java/1.8.0_102.
     *
     * @param url http request url
     */
    public static void imageIO(String url) {
        try {
            HttpURLConnection conn = openValidatedConnection(url);
            try (InputStream is = conn.getInputStream()) {
                ImageIO.read(is); // read response
            }
        } catch (IOException | SSRFException e) {
            logger.error("imageIO failed: {}", e.getClass().getSimpleName());
        }

    }


    /**
     * IOUtils which is wrapped by a validated connection can get remote pictures.
     * Redirects are followed manually and validated.
     *
     * @param url http request url
     */
    public static void IOUtils(String url) {
        try {
            HttpURLConnection conn = openValidatedConnection(url);
            try (InputStream is = conn.getInputStream()) {
                IOUtils.toByteArray(is);
            }
        } catch (IOException | SSRFException e) {
            logger.error("IOUtils failed: {}", e.getClass().getSimpleName());
        }
    }


    public static String HttpAsyncClients(String url) {
        CloseableHttpAsyncClient httpclient = null;
        try {
            URI uri = SSRFChecker.validateHttpUrl(url);
            httpclient = HttpAsyncClients.custom()
                    .setDefaultRequestConfig(RequestConfig.custom().setRedirectsEnabled(false).build())
                    .build();
            httpclient.start();
            final HttpGet request = new HttpGet(uri);
            Future<HttpResponse> future = httpclient.execute(request, null);
            HttpResponse response = future.get(6000, TimeUnit.MILLISECONDS);
            return EntityUtils.toString(response.getEntity());
        } catch (Exception e) {
            logger.error("HttpAsyncClients failed: {}", e.getClass().getSimpleName());
            return REQUEST_FAILED;
        } finally {
            try {
                if (httpclient != null) {
                    httpclient.close();
                }
            } catch (Exception e) {
                logger.error("HttpAsyncClients close failed: {}", e.getClass().getSimpleName());
            }
        }
    }
}
