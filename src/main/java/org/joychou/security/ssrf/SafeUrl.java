package org.joychou.security.ssrf;

import org.apache.http.HttpEntity;
import org.apache.http.HttpHost;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.CloseableHttpResponse;
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

import java.io.ByteArrayInputStream;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * An outbound URL that has been parsed exactly once and whose destination has been resolved and
 * validated exactly once.
 *
 * <ul>
 *   <li>the URL is parsed once with a strict anchored grammar (no URI/URL object); only https without user info is accepted (plain http only when
 *       explicitly enabled with <code>ssrf.allow.http=true</code> / <code>SSRF_ALLOW_HTTP=true</code>);</li>
 *   <li>the host is resolved with {@link InetAddress#getAllByName(String)} and the URL is rejected when
 *       <b>any</b> resolved address is loopback / link-local (cloud metadata 169.254.169.254) / site-local /
 *       any-local / multicast / otherwise non-routable;</li>
 *   <li>optionally the host must be inside the allowlist configured with the system property
 *       <code>ssrf.allowed.hosts</code> or the environment variable <code>SSRF_ALLOWED_HOSTS</code>
 *       (comma separated, a host entry also allows its sub domains);</li>
 *   <li>the connection is then made to the <b>resolved address</b> (address pinning through a custom
 *       {@link DnsResolver}), so a second DNS answer (DNS rebinding) can never change the destination. The
 *       original Host header, TLS SNI and certificate checks still use the original host name. Redirects are
 *       never followed.</li>
 * </ul>
 */
public final class SafeUrl {

    private static final String ILLEGAL_URL = "Illegal url";
    private static final int MAX_URL_LENGTH = 2048;
    private static final int CONNECT_TIMEOUT_MS = 5 * 1000;
    private static final int READ_TIMEOUT_MS = 10 * 1000;

    private static final Pattern NUMERIC_HOST = Pattern.compile("^[0-9.]+$");
    private static final Pattern CANONICAL_IPV4 = Pattern.compile(
            "^(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])$");
    private static final Pattern HOST_NAME = Pattern.compile("^[a-z0-9.-]{1,253}$");

    /** 1 scheme, 2 host (name, IPv4 or bracketed IPv6), 3 port, 4 path, 5 query; the fragment is dropped. */
    private static final Pattern URL_GRAMMAR = Pattern.compile(
            "^(?i:(https?))://([A-Za-z0-9.-]{1,253}|\\[[0-9A-Fa-f:.]{2,45}\\])(?::([0-9]{1,5}))?"
                    + "(/[^?#]*)?(?:\\?([^#]*))?(?:#.*)?$");

    private static final String HEX = "0123456789ABCDEF";
    /** RFC 3986 unreserved + sub-delims + ':' '@' '/' (pchar and '/'), '%' is handled separately. */
    private static final String PATH_ALLOWED =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~!$&'()*+,;=:@/";
    private static final String QUERY_ALLOWED = PATH_ALLOWED + "?";

    private final String scheme;
    private final String hostName;   // without IPv6 brackets
    private final boolean ipv6Literal;
    private final int port;
    private final String rawPath;
    private final String rawQuery;
    private final InetAddress address;

    private SafeUrl(String scheme, String hostName, boolean ipv6Literal, int port,
                    String rawPath, String rawQuery, InetAddress address) {
        this.scheme = scheme;
        this.hostName = hostName;
        this.ipv6Literal = ipv6Literal;
        this.port = port;
        this.rawPath = rawPath == null ? "" : rawPath;
        this.rawQuery = rawQuery;
        this.address = address;
    }

    /**
     * Parse and validate an untrusted URL.
     *
     * @throws SSRFException when the URL is malformed, not https, not allowlisted or resolves to a
     *                       non-public address
     */
    public static SafeUrl parse(String url) {
        if (url == null || url.isEmpty() || url.length() > MAX_URL_LENGTH) {
            throw new SSRFException(ILLEGAL_URL);
        }
        for (int i = 0; i < url.length(); i++) {
            char c = url.charAt(i);
            if (c <= 0x20 || c == 0x7f || c == '\\') {
                throw new SSRFException(ILLEGAL_URL);
            }
        }

        // Strict, anchored grammar: scheme "://" host [":" port] [path] ["?" query] ["#" fragment]. User info
        // ('@'), backslashes and whitespace can not match. No URI/URL object is ever built from the raw input.
        Matcher m = URL_GRAMMAR.matcher(url);
        if (!m.matches()) {
            throw new SSRFException(ILLEGAL_URL);
        }

        // The scheme that is used from here on is a literal chosen by this switch, never the user's string.
        // https is required unless plain http is explicitly enabled (ssrf.allow.http=true / SSRF_ALLOW_HTTP=true).
        final String scheme;
        switch (m.group(1).toLowerCase(Locale.ROOT)) {
            case "https":
                scheme = "https";
                break;
            case "http":
                if (!httpAllowed()) {
                    throw new SSRFException(ILLEGAL_URL);
                }
                scheme = "http";
                break;
            default:
                throw new SSRFException(ILLEGAL_URL);
        }

        // Port is a validated int (-1 = scheme default).
        int port = -1;
        if (m.group(3) != null) {
            port = Integer.parseInt(m.group(3));
            if (port < 1 || port > 65535) {
                throw new SSRFException(ILLEGAL_URL);
            }
        }

        String uriHost = m.group(2);
        boolean ipv6 = uriHost.startsWith("[") && uriHost.endsWith("]");
        String name = (ipv6 ? uriHost.substring(1, uriHost.length() - 1) : uriHost).toLowerCase(Locale.ROOT);
        if (!ipv6) {
            if (!HOST_NAME.matcher(name).matches()) {
                throw new SSRFException(ILLEGAL_URL);
            }
            // Numeric hosts must be canonical dotted-quad: no octal / decimal / short IPv4 spellings.
            if (NUMERIC_HOST.matcher(name).matches() && !CANONICAL_IPV4.matcher(name).matches()) {
                throw new SSRFException(ILLEGAL_URL);
            }
        }
        checkAllowedHost(name);

        InetAddress[] addresses;
        try {
            addresses = InetAddress.getAllByName(name);
        } catch (UnknownHostException e) {
            throw new SSRFException(ILLEGAL_URL);
        }
        if (addresses == null || addresses.length == 0) {
            throw new SSRFException(ILLEGAL_URL);
        }
        // Every record must be public, otherwise an attacker could publish one public and one internal A record.
        for (InetAddress candidate : addresses) {
            if (SSRFChecker.isInternalAddress(candidate)) {
                throw new SSRFException(ILLEGAL_URL);
            }
        }
        // Path and query are not copied: they are rebuilt from a fixed alphabet (see encode).
        String path = encode(m.group(4), PATH_ALLOWED);
        String query = m.group(5) == null ? null : encode(m.group(5), QUERY_ALLOWED);
        return new SafeUrl(scheme, name, ipv6, port, path, query, addresses[0]);
    }

    /**
     * Rebuild a path / query component from a strict character class. Every output character is taken from
     * a constant table: characters of the input that are RFC 3986 unreserved / sub-delims / ':' '@' '/' (and
     * '?' in the query) are looked up in <code>allowed</code>, an existing valid percent escape is re-emitted
     * from {@link #HEX}, everything else (including every non ASCII byte, as UTF-8) is percent-encoded.
     */
    private static String encode(String component, String allowed) {
        if (component == null || component.isEmpty()) {
            return "";
        }
        byte[] in = component.getBytes(StandardCharsets.UTF_8);
        StringBuilder out = new StringBuilder(in.length + 16);
        for (int i = 0; i < in.length; i++) {
            int b = in[i] & 0xff;
            if (b == '%' && i + 2 < in.length && hexValue(in[i + 1]) >= 0 && hexValue(in[i + 2]) >= 0) {
                out.append('%').append(HEX.charAt(hexValue(in[i + 1]))).append(HEX.charAt(hexValue(in[i + 2])));
                i += 2;
                continue;
            }
            int idx = b < 0x80 ? allowed.indexOf((char) b) : -1;
            if (idx >= 0) {
                out.append(allowed.charAt(idx));
            } else {
                out.append('%').append(HEX.charAt(b >> 4)).append(HEX.charAt(b & 0x0f));
            }
        }
        return out.toString();
    }

    private static int hexValue(byte b) {
        return b < 0 ? -1 : HEX.indexOf(Character.toUpperCase((char) b));
    }

    /**
     * Plain http is rejected by default. It can only be enabled explicitly with the system property
     * <code>ssrf.allow.http=true</code> or the environment variable <code>SSRF_ALLOW_HTTP=true</code>.
     */
    private static boolean httpAllowed() {
        return Boolean.parseBoolean(System.getProperty("ssrf.allow.http", System.getenv("SSRF_ALLOW_HTTP")));
    }

    private static void checkAllowedHost(String name) {
        String configured = System.getProperty("ssrf.allowed.hosts", System.getenv("SSRF_ALLOWED_HOSTS"));
        if (configured == null || configured.trim().isEmpty()) {
            return; // no allowlist configured: the address checks above are the control
        }
        for (String entry : configured.split(",")) {
            String allowed = entry.trim().toLowerCase(Locale.ROOT);
            if (!allowed.isEmpty() && (name.equals(allowed) || name.endsWith("." + allowed))) {
                return;
            }
        }
        throw new SSRFException(ILLEGAL_URL);
    }

    public boolean isHttps() {
        return "https".equals(scheme);
    }

    /** Host name without IPv6 brackets, lower case. */
    public String getHostName() {
        return hostName;
    }

    /** Value for the HTTP Host header (original host name plus explicit port, if any). */
    public String getHostHeader() {
        String host = ipv6Literal ? "[" + hostName + "]" : hostName;
        return port == -1 ? host : host + ":" + port;
    }

    /** Explicit port of the url, or -1 when none was given. */
    public int getPort() {
        return port;
    }

    /** The single validated address that every connection must use. */
    public InetAddress getAddress() {
        return address;
    }

    private String pathAndQuery() {
        StringBuilder sb = new StringBuilder();
        sb.append(rawPath.isEmpty() ? "/" : rawPath);
        if (rawQuery != null) {
            sb.append('?').append(rawQuery);
        }
        return sb.toString();
    }

    /** Literal IP of the pinned address, usable as a host in non-HTTP URLs (IPv6 in brackets). */
    public String getAddressLiteral() {
        String ip = address.getHostAddress();
        int scope = ip.indexOf('%');
        if (scope >= 0) {
            ip = ip.substring(0, scope);
        }
        return address instanceof java.net.Inet6Address ? "[" + ip + "]" : ip;
    }

    /** URL rebuilt from the validated components, keeping the original host name. */
    public String nameUrl() {
        StringBuilder sb = new StringBuilder(scheme).append("://").append(getHostHeader());
        return sb.append(pathAndQuery()).toString();
    }

    /**
     * HTTP client whose DNS resolution is pinned to the address validated in {@link #parse(String)}: whatever
     * name the client asks for, it only ever connects to that one address (DNS rebinding cannot swap it).
     * The request still carries the original Host header and, for https, SNI plus certificate and host name
     * verification use the original host name. Redirects are disabled and timeouts are set.
     */
    public CloseableHttpClient newClient() {
        RegistryBuilder<ConnectionSocketFactory> registryBuilder = RegistryBuilder.<ConnectionSocketFactory>create()
                .register("https", SSLConnectionSocketFactory.getSocketFactory());
        if (httpAllowed()) {
            registryBuilder.register("http", PlainConnectionSocketFactory.getSocketFactory());
        }
        Registry<ConnectionSocketFactory> registry = registryBuilder.build();
        final InetAddress pinned = this.address;
        DnsResolver pinnedResolver = new DnsResolver() {
            @Override
            public InetAddress[] resolve(String host) {
                return new InetAddress[]{pinned};
            }
        };
        PoolingHttpClientConnectionManager connectionManager =
                new PoolingHttpClientConnectionManager(registry, pinnedResolver);
        RequestConfig config = RequestConfig.custom()
                .setRedirectsEnabled(false)
                .setConnectTimeout(CONNECT_TIMEOUT_MS)
                .setConnectionRequestTimeout(CONNECT_TIMEOUT_MS)
                .setSocketTimeout(READ_TIMEOUT_MS)
                .build();
        return HttpClients.custom()
                .setConnectionManager(connectionManager)
                .setDefaultRequestConfig(config)
                .disableRedirectHandling()
                .disableAutomaticRetries()
                .build();
    }

    /**
     * Execute a GET against the validated destination only. The request is assembled exclusively from derived
     * data: the scheme is a constant literal chosen in {@link #parse(String)}, the connect address is the
     * resolved, validated {@link InetAddress}, the port is a validated int and the request target is the
     * path/query rebuilt by {@link #encode(String, String)}. The untrusted URL string (or any object
     * made from it) is never handed to the HTTP client.
     *
     * @param cookie optional Cookie request header value
     */
    public CloseableHttpResponse execute(CloseableHttpClient client, String cookie) throws IOException {
        final String literalScheme = "https".equals(scheme) ? "https" : "http";
        final int effectivePort = port != -1 ? port : ("https".equals(literalScheme) ? 443 : 80);
        HttpHost target = new HttpHost(address, ipv6Literal ? "[" + hostName + "]" : hostName,
                effectivePort, literalScheme);
        HttpGet get = new HttpGet(pathAndQuery());
        if (cookie != null) {
            get.setHeader("Cookie", cookie);
        }
        return client.execute(target, get);
    }

    /** Same as {@link #open(String)} without extra headers. */
    public InputStream open() throws IOException {
        return open(null);
    }

    /**
     * GET the validated URL through the pinned client and return the body stream. Closing the stream releases the
     * connection and the client. HTTP status 4xx/5xx raise an {@link IOException}; 3xx are not followed.
     *
     * @param cookie optional Cookie request header value
     */
    public InputStream open(String cookie) throws IOException {
        final CloseableHttpClient client = newClient();
        boolean opened = false;
        try {
            final CloseableHttpResponse response = execute(client, cookie);
            int status = response.getStatusLine().getStatusCode();
            HttpEntity entity = response.getEntity();
            if (status >= 400 || entity == null) {
                response.close();
                if (status >= 400) {
                    throw new IOException("Server returned HTTP response code: " + status);
                }
                client.close();
                opened = true;
                return new ByteArrayInputStream(new byte[0]);
            }
            InputStream body = entity.getContent();
            opened = true;
            return new FilterInputStream(body) {
                @Override
                public void close() throws IOException {
                    try {
                        super.close();
                    } finally {
                        try {
                            response.close();
                        } finally {
                            client.close();
                        }
                    }
                }
            };
        } finally {
            if (!opened) {
                client.close();
            }
        }
    }
}
