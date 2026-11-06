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
import java.net.InetAddress;
import java.net.URI;
import java.net.URL;
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
        logger.error("Request failed: {}", e.getClass().getSimpleName());
        return "Request failed";
    }

    /**
     * Build a URL from the components of a URI that was validated by
     * {@link SSRFChecker#requireSafeUri(String)}. The scheme is a literal.
     */
    private static URL toSafeUrl(URI uri) throws IOException {
        String scheme = uri.getScheme();
        String host = uri.getHost();
        if (host == null || scheme == null) {
            throw new SSRFException("[-] SSRF check failed. Illegal URL");
        }
        String safeScheme;
        if ("https".equalsIgnoreCase(scheme)) {
            safeScheme = "https";
        } else if ("http".equalsIgnoreCase(scheme)) {
            safeScheme = "http";
        } else {
            throw new SSRFException("[-] SSRF check failed. Only http and https are allowed");
        }
        String path = uri.getRawPath() == null ? "" : uri.getRawPath();
        String file = uri.getRawQuery() == null ? path : path + "?" + uri.getRawQuery();
        return new URL(safeScheme, host, uri.getPort(), file);
    }


    /**
     * Open a validated http/https URI without following redirects.
     */
    private static HttpURLConnection openNoRedirect(URI uri) throws IOException {
        String scheme = uri.getScheme();
        if (scheme == null || !(scheme.equals("http") || scheme.equals("https")) || uri.getHost() == null) {
            throw new SSRFException("[-] SSRF check failed. Only http and https are allowed");
        }
        HttpURLConnection conn = (HttpURLConnection) toSafeUrl(uri).openConnection();
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
            method = new GetMethod(toSafeUrl(SSRFChecker.requireSafeUri(url)).toExternalForm());
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


    /**
     * GET a validated http/https URI while connecting only to the addresses that were resolved and
     * checked here. The host name is resolved exactly once, every address is verified to be public,
     * and the HTTP client is given a resolver that returns only those addresses, so a DNS rebind
     * (a second lookup with a different, internal answer) cannot redirect the connection.
     * Redirects are not followed.
     *
     * @param uri URI returned by {@link SSRFChecker#requireSafeUri(String)}
     * @throws SSRFException if the host cannot be resolved or resolves to an internal address
     */
    public static String getPinned(URI uri) {
        try {
            // re-validate and re-serialise so only checked components reach the client
            final URI safeUri = SSRFChecker.requireSafeUri(uri.toString());
            String host = safeUri.getHost();
            if (host == null) {
                throw new SSRFException("[-] SSRF check failed. Host is empty");
            }
            final InetAddress[] pinned = InetAddress.getAllByName(host); // single DNS lookup
            for (InetAddress address : pinned) {
                if (SSRFChecker.isInternalIp(address.getHostAddress())) {
                    throw new SSRFException("[-] SSRF check failed. Internal host: " + host);
                }
            }
            try (CloseableHttpClient client = HttpClients.custom()
                    .setDnsResolver(name -> pinned)
                    .disableRedirectHandling()
                    .build()) {
                HttpGet httpGet = new HttpGet(safeUri);
                httpGet.setConfig(RequestConfig.custom().setRedirectsEnabled(false).build());
                HttpResponse httpResponse = client.execute(httpGet); // send request
                return EntityUtils.toString(httpResponse.getEntity());
            }
        } catch (SSRFException | IOException e) {
            return requestFailed(e);
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
            URI safeUri = SSRFChecker.requireSafeUri(url);
            Document doc = Jsoup.connect(toSafeUrl(safeUri).toExternalForm())
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
        com.squareup.okhttp.Request ok_http = new com.squareup.okhttp.Request.Builder().url(toSafeUrl(uri)).build();
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
