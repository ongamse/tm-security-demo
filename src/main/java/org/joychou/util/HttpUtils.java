package org.joychou.util;

import org.apache.commons.io.IOUtils;
import org.joychou.security.ssrf.SSRFException;
import org.joychou.security.ssrf.SafeUrl;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.imageio.ImageIO;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;

/**
 * Outbound HTTP helpers. Every method follows the same structure:
 * <ol>
 *   <li>{@link SafeUrl#parse(String)} parses the untrusted url once into a {@link java.net.URI}, requires
 *       http/https, resolves every address of the host and rejects loopback / link-local (169.254.169.254) /
 *       site-local / any-local / multicast / blocked addresses (and hosts outside the optional
 *       <code>ssrf.allowed.hosts</code> allowlist);</li>
 *   <li>the request is then sent through a client pinned to the validated address (the original Host header is
 *       kept), so DNS rebinding between check and use cannot change the destination;</li>
 *   <li>redirects are never followed.</li>
 * </ol>
 *
 * @author JoyChou 2020-04-06
 */
public class HttpUtils {

    private final static Logger logger = LoggerFactory.getLogger(HttpUtils.class);

    private static final String ILLEGAL_URL = "Illegal url";

    private static String readLines(InputStream is) throws IOException {
        try (BufferedReader in = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8))) {
            String inputLine;
            StringBuilder html = new StringBuilder();
            while ((inputLine = in.readLine()) != null) {
                html.append(inputLine);
            }
            return html.toString();
        }
    }

    private static String readAll(InputStream is) throws IOException {
        try (InputStream in = is) {
            return new String(IOUtils.toByteArray(in), StandardCharsets.UTF_8);
        }
    }

    public static String commonHttpClient(String url) {
        try {
            return readAll(SafeUrl.parse(url).open());
        } catch (SSRFException e) {
            return ILLEGAL_URL;
        } catch (IOException e) {
            return "Error: " + e.getMessage();
        }
    }


    public static String request(String url) {
        try {
            return readAll(SafeUrl.parse(url).open());
        } catch (SSRFException e) {
            return ILLEGAL_URL;
        } catch (Exception e) {
            return e.getMessage();
        }
    }


    public static String httpClient(String url) {
        try {
            return readLines(SafeUrl.parse(url).open());
        } catch (SSRFException e) {
            return ILLEGAL_URL;
        } catch (Exception e) {
            return e.getMessage();
        }
    }


    public static String URLConnection(String url) {
        try {
            return readLines(SafeUrl.parse(url).open());
        } catch (SSRFException e) {
            return ILLEGAL_URL;
        } catch (Exception e) {
            logger.error(e.getMessage());
            return e.getMessage();
        }
    }


    /**
     * Redirects are not followed and the connection is pinned to the validated address.
     */
    public static String HttpURLConnection(String url) {
        try {
            return readLines(SafeUrl.parse(url).open());
        } catch (SSRFException e) {
            return ILLEGAL_URL;
        } catch (IOException e) {
            logger.error(e.getMessage());
            return e.getMessage();
        }
    }


    /**
     * Jsoup is a HTML parser about Java. The page is fetched through the pinned client and only parsed by Jsoup.
     *
     * @param url http request url
     */
    public static String Jsoup(String url) {
        try {
            SafeUrl safeUrl = SafeUrl.parse(url);
            try (InputStream is = safeUrl.open("name=joychou")) { // request cookies
                Document doc = Jsoup.parse(is, "UTF-8", safeUrl.nameUrl());
                return doc.outerHtml();
            }
        } catch (SSRFException e) {
            return ILLEGAL_URL;
        } catch (IOException e) {
            return e.getMessage();
        }
    }


    /**
     * Redirects are not followed and the connection is pinned to the validated address.
     */
    public static String okhttp(String url) throws IOException {
        try {
            return readAll(SafeUrl.parse(url).open());
        } catch (SSRFException e) {
            return ILLEGAL_URL;
        }
    }


    /**
     * Only remote http(s) resources on public hosts are read; file:, jar: etc. are rejected.
     *
     * @param url http request url
     */
    public static void imageIO(String url) {
        try (InputStream is = SafeUrl.parse(url).open()) { // send request
            ImageIO.read(is);
        } catch (SSRFException e) {
            logger.error("Blocked illegal url");
        } catch (IOException e) {
            logger.error(e.getMessage());
        }
    }


    /**
     * Read the remote resource through the pinned client.
     *
     * @param url http request url
     */
    public static void IOUtils(String url) {
        try (InputStream is = SafeUrl.parse(url).open()) {
            IOUtils.toByteArray(is);
        } catch (SSRFException e) {
            logger.error("Blocked illegal url");
        } catch (IOException e) {
            logger.error(e.getMessage());
        }
    }


    public static String HttpAsyncClients(String url) {
        try {
            return readAll(SafeUrl.parse(url).open());
        } catch (SSRFException e) {
            return ILLEGAL_URL;
        } catch (Exception e) {
            return e.getMessage();
        }
    }
}
