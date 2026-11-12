package org.joychou.util;

import com.squareup.okhttp.OkHttpClient;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.methods.GetMethod;
import org.apache.commons.httpclient.params.HttpConnectionParams;
import org.apache.commons.httpclient.protocol.Protocol;
import org.apache.commons.httpclient.protocol.ProtocolSocketFactory;
import org.apache.commons.httpclient.protocol.SecureProtocolSocketFactory;
import org.apache.commons.io.IOUtils;
import org.apache.http.HttpResponse;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.fluent.Executor;
import org.apache.http.client.fluent.Request;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.config.Registry;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.conn.DnsResolver;
import org.apache.http.conn.socket.ConnectionSocketFactory;
import org.apache.http.conn.socket.PlainConnectionSocketFactory;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;
import org.apache.http.impl.nio.client.CloseableHttpAsyncClient;
import org.apache.http.impl.nio.client.HttpAsyncClients;
import org.apache.http.util.EntityUtils;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.joychou.security.SecurityUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.imageio.ImageIO;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URLConnection;
import java.net.UnknownHostException;
import java.util.concurrent.*;

/**
 * @author JoyChou 2020-04-06
 */
public class HttpUtils {

    private final static Logger logger = LoggerFactory.getLogger(HttpUtils.class);

    /**
     * Validate a user supplied url before the server requests it (SSRF defense).
     * Only absolute http/https urls whose host resolves exclusively to public addresses are accepted.
     * All clients below also disable redirect following, so a redirect can never lead to a target
     * that was not validated.
     *
     * @param url http request url
     * @return the validated url as URI, used for the request so that validation and request parse the same value
     * @throws IOException if the url is not allowed
     */
    private static URI checkedUri(String url) throws IOException {
        return URI.create(checkedTarget(url).toUriString());
    }


    /**
     * Validate a user supplied url and return the parsed target. The target is rebuilt from the
     * validated components (see {@link SecurityUtil#checkHttpTarget(String)}), so the request is never
     * made with the original request string.
     *
     * @throws IOException if the url is not allowed
     */
    private static SecurityUtil.HttpTarget checkedTarget(String url) throws IOException {
        SecurityUtil.HttpTarget target = SecurityUtil.checkHttpTarget(url);
        if (target == null) {
            throw new IOException("[-] SSRF check failed. Illegal url.");
        }
        return target;
    }


    /**
     * Socket factory for commons-httpclient 3.x: resolves the host once, requires every resolved address
     * to be public and connects to exactly that address (no second lookup by name, so DNS rebinding cannot
     * swap the address between check and use). For https the TLS session is layered on the connected
     * socket with the host name for SNI and endpoint (host name) verification.
     */
    private static class PublicOnlySocketFactory implements ProtocolSocketFactory {
        private final boolean tls;

        private PublicOnlySocketFactory(boolean tls) {
            this.tls = tls;
        }

        @Override
        public Socket createSocket(String host, int port, InetAddress localAddress, int localPort,
                                   HttpConnectionParams params) throws IOException {
            InetAddress[] addresses = SecurityUtil.resolvePublicAddresses(host);
            if (addresses == null) {
                throw new UnknownHostException("[-] SSRF check failed. Illegal host.");
            }
            Socket socket = new Socket();
            try {
                if (localAddress != null) {
                    socket.bind(new InetSocketAddress(localAddress, localPort));
                }
                socket.connect(new InetSocketAddress(addresses[0], port),
                        params == null ? 0 : params.getConnectionTimeout());
                return tls ? layerTls(socket, host, port) : socket;
            } catch (IOException e) {
                socket.close();
                throw e;
            }
        }

        @Override
        public Socket createSocket(String host, int port, InetAddress localAddress, int localPort)
                throws IOException {
            return createSocket(host, port, localAddress, localPort, null);
        }

        @Override
        public Socket createSocket(String host, int port) throws IOException {
            return createSocket(host, port, null, 0, null);
        }

        static Socket layerTls(Socket socket, String host, int port) throws IOException {
            String sniHost = host.startsWith("[") ? host.substring(1, host.length() - 1) : host;
            SSLSocket ssl = (SSLSocket) ((SSLSocketFactory) SSLSocketFactory.getDefault())
                    .createSocket(socket, sniHost, port, true);
            SSLParameters sslParameters = ssl.getSSLParameters();
            sslParameters.setEndpointIdentificationAlgorithm("HTTPS");
            ssl.setSSLParameters(sslParameters);
            return ssl;
        }
    }


    /** TLS variant, marked secure for commons-httpclient (Protocol.isSecure). */
    private static final class PublicOnlySecureSocketFactory extends PublicOnlySocketFactory
            implements SecureProtocolSocketFactory {
        private PublicOnlySecureSocketFactory() {
            super(true);
        }

        @Override
        public Socket createSocket(Socket socket, String host, int port, boolean autoClose) throws IOException {
            return layerTls(socket, host, port);
        }
    }


    /**
     * DNS resolver for Apache HttpClient that resolves the host once, requires every resolved address
     * to be public and hands exactly those addresses to the socket. The address that was validated is
     * therefore the address that is connected to (DNS rebinding cannot swap it between check and use).
     */
    private static final DnsResolver PUBLIC_ONLY_DNS_RESOLVER = new DnsResolver() {
        @Override
        public InetAddress[] resolve(String host) throws UnknownHostException {
            InetAddress[] addresses = SecurityUtil.resolvePublicAddresses(host);
            if (addresses == null) {
                throw new UnknownHostException("[-] SSRF check failed. Illegal host.");
            }
            return addresses;
        }
    };


    /**
     * Apache HttpClient that never follows redirects and only connects to validated public addresses.
     */
    private static CloseableHttpClient newCheckedHttpClient() {
        Registry<ConnectionSocketFactory> registry = RegistryBuilder.<ConnectionSocketFactory>create()
                .register("http", PlainConnectionSocketFactory.getSocketFactory())
                .register("https", SSLConnectionSocketFactory.getSocketFactory())
                .build();
        return HttpClients.custom()
                .setConnectionManager(new PoolingHttpClientConnectionManager(registry, PUBLIC_ONLY_DNS_RESOLVER))
                .disableRedirectHandling()
                .build();
    }


    /**
     * Open a connection to a validated url which does not follow redirects.
     */
    private static HttpURLConnection openCheckedConnection(String url) throws IOException {
        HttpURLConnection conn = (HttpURLConnection) checkedUri(url).toURL().openConnection();
        conn.setInstanceFollowRedirects(false);
        return conn;
    }


    public static String commonHttpClient(String url) {

        HttpClient client = new HttpClient();
        GetMethod method = null;

        try {
            SecurityUtil.HttpTarget target = checkedTarget(url);
            boolean tls = "https".equals(target.getScheme());
            Protocol protocol;
            if (tls) {
                protocol = new Protocol("https", (SecureProtocolSocketFactory) new PublicOnlySecureSocketFactory(), 443);
            } else {
                protocol = new Protocol("http", (ProtocolSocketFactory) new PublicOnlySocketFactory(false), 80);
            }
            client.getHostConfiguration().setHost(target.getHost(),
                    target.getPort() == -1 ? protocol.getDefaultPort() : target.getPort(), protocol);
            // Relative request uri: the connection goes to the pinned, validated host configuration.
            method = new GetMethod(target.getPathAndQuery());
            method.setFollowRedirects(false);
            client.executeMethod(method); // send request
            byte[] resBody = method.getResponseBody();
            return new String(resBody);

        } catch (IOException | IllegalArgumentException e) {
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
            CloseableHttpClient client = newCheckedHttpClient();
            try {
                return Executor.newInstance(client)
                        .execute(Request.Get(checkedUri(url)))
                        .returnContent().toString();
            } finally {
                client.close();
            }
        } catch (Exception e) {
            return e.getMessage();
        }
    }


    public static String httpClient(String url) {

        StringBuilder result = new StringBuilder();

        try {

            CloseableHttpClient client = newCheckedHttpClient();
            HttpGet httpGet = new HttpGet(checkedUri(url));
            // never follow redirects to a target that was not validated
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
            URLConnection urlConnection = openCheckedConnection(url);
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
            HttpURLConnection conn = openCheckedConnection(url);
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
            URI target = checkedUri(url);
            // Fetch with the pinned-DNS client (validated address, no redirects) and let Jsoup only parse.
            CloseableHttpClient client = newCheckedHttpClient();
            try {
                HttpGet httpGet = new HttpGet(target);
                httpGet.setConfig(RequestConfig.custom()
                        .setRedirectsEnabled(false)
                        .setConnectTimeout(3000)
                        .setSocketTimeout(3000)
                        .build());
                httpGet.setHeader("Cookie", "name=joychou"); // request cookies
                HttpResponse response = client.execute(httpGet);
                int status = response.getStatusLine().getStatusCode();
                if (status >= 400 || response.getEntity() == null) {
                    throw new IOException("HTTP error fetching URL. Status=" + status);
                }
                Document doc = Jsoup.parse(response.getEntity().getContent(), null, target.toString());
                return doc.outerHtml();
            } finally {
                client.close();
            }
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
        URL checkedUrl = checkedUri(url).toURL();
        OkHttpClient client = new OkHttpClient();
        client.setFollowRedirects(false);
        client.setFollowSslRedirects(false);
        com.squareup.okhttp.Request ok_http = new com.squareup.okhttp.Request.Builder().url(checkedUrl).build();
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
            // Only remote public http(s) pictures; reject file:, jar:, internal hosts, etc.
            HttpURLConnection conn = openCheckedConnection(url);
            try (InputStream in = conn.getInputStream()) { // send request
                ImageIO.read(in);
            } finally {
                conn.disconnect();
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
            IOUtils.toByteArray(openCheckedConnection(url));
        } catch (IOException e) {
            logger.error(e.getMessage());
        }
    }


    public static String HttpAsyncClients(String url) {
        CloseableHttpAsyncClient httpclient = HttpAsyncClients.custom()
                .setDefaultRequestConfig(RequestConfig.custom().setRedirectsEnabled(false).build())
                .build();
        try {
            final HttpGet request = new HttpGet(checkedUri(url));
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
