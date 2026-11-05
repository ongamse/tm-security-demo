package org.joychou.util;

import com.squareup.okhttp.OkHttpClient;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.methods.GetMethod;
import org.apache.commons.io.IOUtils;
import org.apache.http.HttpResponse;
import org.apache.http.ProtocolException;
import org.apache.http.client.fluent.Executor;
import org.apache.http.client.fluent.Request;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.DefaultRedirectStrategy;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.nio.client.CloseableHttpAsyncClient;
import org.apache.http.impl.nio.client.HttpAsyncClients;
import org.apache.http.protocol.HttpContext;
import org.apache.http.util.EntityUtils;
import org.joychou.security.ssrf.SSRFChecker;
import org.joychou.security.ssrf.SSRFException;
import org.jsoup.Connection;
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
import java.net.URL;
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
    private static final long MAX_IMAGE_BYTES = 10L * 1024 * 1024;
    // Fixed messages returned to callers; exception text is never returned or embedded in a response.
    private static final String ERROR_MESSAGE = "Request failed";
    private static final String BLOCKED_MESSAGE = "Request blocked";

    public static String commonHttpClient(String url) {

        // scheme/host validated and url rebuilt from the validated components
        URL checked;
        try {
            checked = SSRFChecker.checkAndGetUrl(url);
        } catch (SSRFException e) {
            logger.error("[-] Request blocked: {}", e.getClass().getSimpleName());
            return BLOCKED_MESSAGE;
        }
        HttpClient client = new HttpClient();
        GetMethod method = new GetMethod(checked.toString());

        try {
            client.executeMethod(method); // send request
            byte[] resBody = method.getResponseBody();
            return new String(resBody);

        } catch (IOException e) {
            logger.error("[-] Request failed: {}", e.getClass().getSimpleName());
            return ERROR_MESSAGE;
        } finally {
            // Release the connection.
            method.releaseConnection();
        }
    }


    public static String request(String url) {
        try {
            URL checked = SSRFChecker.checkAndGetUrl(url);
            CloseableHttpClient client = HttpClients.custom()
                    .setRedirectStrategy(new CheckedRedirectStrategy())
                    .build();
            try {
                return Executor.newInstance(client)
                        .execute(Request.Get(checked.toURI()))
                        .returnContent().toString();
            } finally {
                client.close();
            }
        } catch (SSRFException e) {
            logger.error("[-] Request blocked: {}", e.getClass().getSimpleName());
            return BLOCKED_MESSAGE;
        } catch (Exception e) {
            logger.error("[-] Request failed: {}", e.getClass().getSimpleName());
            return ERROR_MESSAGE;
        }
    }


    /**
     * Redirect strategy which validates every redirect target with {@link SSRFChecker#checkAndGetUrl(String)}.
     */
    private static class CheckedRedirectStrategy extends DefaultRedirectStrategy {
        @Override
        public URI getLocationURI(org.apache.http.HttpRequest request, HttpResponse response, HttpContext context)
                throws ProtocolException {
            URI target = super.getLocationURI(request, response, context);
            try {
                // return the URI rebuilt from the validated components, not the Location header value
                return SSRFChecker.checkAndGetUrl(target.toString()).toURI();
            } catch (SSRFException | java.net.URISyntaxException e) {
                throw new ProtocolException("[-] SSRF check failed. Illegal redirect.");
            }
        }
    }


    /**
     * Open a connection to an untrusted url. The scheme must be http/https and the host must not resolve to an
     * internal address. Redirects are followed manually (at most {@link #MAX_REDIRECTS}) and every hop is validated again.
     *
     * @param url untrusted url
     * @return connected HttpURLConnection to the final, validated url
     * @throws SSRFException if the url or one of its redirect targets is not allowed
     */
    public static HttpURLConnection openCheckedConnection(String url) throws IOException {
        return openCheckedConnection(SSRFChecker.checkAndGetUrl(url));
    }


    /**
     * Same as {@link #openCheckedConnection(String)} but starts from a url that was already returned by
     * {@link SSRFChecker#checkAndGetUrl(String)} (http/https only). Every redirect target is validated again.
     *
     * @param checked url returned by SSRFChecker.checkAndGetUrl
     * @return connected HttpURLConnection to the final, validated url
     * @throws SSRFException if one of the redirect targets is not allowed
     */
    public static HttpURLConnection openCheckedConnection(URL checked) throws IOException {
        URL current = checked;
        for (int i = 0; i <= MAX_REDIRECTS; i++) {
            URL u = current;
            HttpURLConnection conn = (HttpURLConnection) u.openConnection();
            conn.setInstanceFollowRedirects(false);
            conn.setConnectTimeout(CONNECT_TIMEOUT_MS);
            conn.setReadTimeout(READ_TIMEOUT_MS);
            int code = conn.getResponseCode();
            if (code == 301 || code == 302 || code == 303 || code == 307 || code == 308) {
                String location = conn.getHeaderField("Location");
                if (location == null) {
                    return conn;
                }
                current = SSRFChecker.checkAndGetUrl(SSRFChecker.resolveRedirect(u, location));
                conn.disconnect();
                continue;
            }
            return conn;
        }
        throw new IOException("Too many redirects");
    }


    /**
     * Read at most {@link #MAX_IMAGE_BYTES} bytes from the stream.
     *
     * @throws IOException if the stream is larger than the limit
     */
    private static byte[] readBounded(InputStream is) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        long total = 0;
        int n;
        while ((n = is.read(buf)) != -1) {
            total += n;
            if (total > MAX_IMAGE_BYTES) {
                throw new IOException("Response too large");
            }
            out.write(buf, 0, n);
        }
        return out.toByteArray();
    }


    public static String httpClient(String url) {

        StringBuilder result = new StringBuilder();

        try {

            // scheme/host validated, url rebuilt from validated components, every redirect hop re-validated
            URL checked = SSRFChecker.checkAndGetUrl(url);
            CloseableHttpClient client = HttpClients.custom()
                    .setRedirectStrategy(new CheckedRedirectStrategy())
                    .build();
            try {
                HttpGet httpGet = new HttpGet(checked.toURI());
                HttpResponse httpResponse = client.execute(httpGet); // send request
                BufferedReader rd = new BufferedReader(new InputStreamReader(httpResponse.getEntity().getContent()));

                String line;
                while ((line = rd.readLine()) != null) {
                    result.append(line);
                }
            } finally {
                client.close();
            }

            return result.toString();

        } catch (SSRFException e) {
            logger.error("[-] Request blocked: {}", e.getClass().getSimpleName());
            return BLOCKED_MESSAGE;
        } catch (Exception e) {
            logger.error("[-] Request failed: {}", e.getClass().getSimpleName());
            return ERROR_MESSAGE;
        }
    }


    public static String URLConnection(String url) {
        try {
            HttpURLConnection urlConnection = openCheckedConnection(url);
            BufferedReader in = new BufferedReader(new InputStreamReader(urlConnection.getInputStream())); //send request
            String inputLine;
            StringBuilder html = new StringBuilder();

            while ((inputLine = in.readLine()) != null) {
                html.append(inputLine);
            }
            in.close();
            return html.toString();
        } catch (SSRFException e) {
            logger.error("[-] Request blocked: {}", e.getClass().getSimpleName());
            return BLOCKED_MESSAGE;
        } catch (Exception e) {
            logger.error("[-] Request failed: {}", e.getClass().getSimpleName());
            return ERROR_MESSAGE;
        }
    }


    /**
     * The default setting of followRedirects is true.
     * UserAgent is Java/1.8.0_102.
     */
    public static String HttpURLConnection(String url) {
        try {
            // Redirects are followed manually and every hop is validated against SSRF.
            HttpURLConnection conn = openCheckedConnection(url);
            InputStream is = conn.getInputStream();  // send request
            BufferedReader in = new BufferedReader(new InputStreamReader(is));
            String inputLine;
            StringBuilder html = new StringBuilder();

            while ((inputLine = in.readLine()) != null) {
                html.append(inputLine);
            }
            in.close();
            return html.toString();
        } catch (SSRFException e) {
            logger.error("[-] Request blocked: {}", e.getClass().getSimpleName());
            return BLOCKED_MESSAGE;
        } catch (IOException e) {
            logger.error("[-] Request failed: {}", e.getClass().getSimpleName());
            return ERROR_MESSAGE;
        }
    }


    /**
     * Jsoup is a HTML parser about Java.
     *
     * @param url http request url
     */
    public static String Jsoup(String url) {
        try {
            String current = url;
            // Redirects are followed manually and every hop is validated against SSRF.
            for (int i = 0; i <= MAX_REDIRECTS; i++) {
                URL checked = SSRFChecker.checkAndGetUrl(current);
                Connection.Response res = Jsoup.connect(checked.toString())
                        .followRedirects(false)
                        .timeout(3000)
                        .cookie("name", "joychou") // request cookies
                        .execute();
                int code = res.statusCode();
                String location = res.header("Location");
                if ((code == 301 || code == 302 || code == 303 || code == 307 || code == 308) && location != null) {
                    current = SSRFChecker.resolveRedirect(checked, location);
                    continue;
                }
                Document doc = res.parse();
                return doc.outerHtml();
            }
            return "Too many redirects";
        } catch (SSRFException e) {
            logger.error("[-] Request blocked: {}", e.getClass().getSimpleName());
            return BLOCKED_MESSAGE;
        } catch (IOException e) {
            logger.error("[-] Request failed: {}", e.getClass().getSimpleName());
            return ERROR_MESSAGE;
        }
    }


    /**
     * The default setting of followRedirects is true. The option of followRedirects is true.
     *
     * UserAgent is <code>okhttp/2.5.0</code>.
     */
    public static String okhttp(String url) throws IOException {
        OkHttpClient client = new OkHttpClient();
        // Redirects are followed manually and every hop is validated against SSRF.
        client.setFollowRedirects(false);
        String current = url;
        for (int i = 0; i <= MAX_REDIRECTS; i++) {
            URL checked = SSRFChecker.checkAndGetUrl(current);
            com.squareup.okhttp.Request ok_http = new com.squareup.okhttp.Request.Builder().url(checked).build();
            com.squareup.okhttp.Response response = client.newCall(ok_http).execute();
            int code = response.code();
            String location = response.header("Location");
            if ((code == 301 || code == 302 || code == 303 || code == 307 || code == 308) && location != null) {
                response.body().close();
                current = SSRFChecker.resolveRedirect(checked, location);
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
            // http/https only, internal hosts rejected; only the validated URL object is connected to,
            // redirects re-validated. The image is decoded from a size-bounded in-memory copy of the
            // response stream, never from a file path or a file: url.
            URL checked = SSRFChecker.checkAndGetUrl(url);
            HttpURLConnection conn = openCheckedConnection(checked);
            try (InputStream is = conn.getInputStream()) { // send request
                byte[] body = readBounded(is);
                ImageIO.read(new ByteArrayInputStream(body));
            }
        } catch (IOException e) {
            logger.error("[-] Request failed: {}", e.getClass().getSimpleName());
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
            // validated connection: http/https only, internal hosts rejected, redirects re-validated
            HttpURLConnection conn = openCheckedConnection(url);
            try (InputStream is = conn.getInputStream()) {
                IOUtils.toByteArray(is);
            }
        } catch (IOException e) {
            logger.error("[-] Request failed: {}", e.getClass().getSimpleName());
        }
    }


    public static String HttpAsyncClients(String url) {
        CloseableHttpAsyncClient httpclient = HttpAsyncClients.custom()
                .setRedirectStrategy(new CheckedRedirectStrategy())
                .build();
        try {
            final HttpGet request = new HttpGet(SSRFChecker.checkAndGetUrl(url).toURI());
            httpclient.start();
            Future<HttpResponse> future = httpclient.execute(request, null);
            HttpResponse response = future.get(6000, TimeUnit.MILLISECONDS);
            return EntityUtils.toString(response.getEntity());
        } catch (SSRFException e) {
            logger.error("[-] Request blocked: {}", e.getClass().getSimpleName());
            return BLOCKED_MESSAGE;
        } catch (Exception e) {
            logger.error("[-] Request failed: {}", e.getClass().getSimpleName());
            return ERROR_MESSAGE;
        } finally {
            try {
                httpclient.close();
            } catch (Exception e) {
                logger.error("[-] Request failed: {}", e.getClass().getSimpleName());
            }
        }
    }
}
