package org.joychou.security.ssrf;

import java.io.IOException;
import java.net.InetAddress;
import java.net.URL;
import java.util.Collections;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Single chokepoint that turns a request-derived url string into a validated, rebuilt {@link URL}.
 *
 * <p>The returned URL is built from validated components (a constant scheme literal, the validated host,
 * port, path and query), so callers never pass the original request string to an HTTP client.
 * Redirects are not handled here: callers must keep automatic redirect following disabled.</p>
 *
 * <p>The connection is intentionally not pinned to the resolved IP: HttpURLConnection does not allow
 * overriding the Host header and TLS certificate/SNI validation would fail for an IP literal.
 * The existing socket hook ({@link SocketHookImpl}) covers the rebinding window where it is enabled.</p>
 */
public final class SafeUrl {

    private static final String SSRF_CHECK_FAILED = "[-] SSRF check failed";

    /**
     * Optional allowlist of host suffixes (for example "example.com"). When empty, any external host is allowed.
     */
    private static final List<String> ALLOWED_HOST_SUFFIXES = Collections.emptyList();

    private static final Pattern SAFE_HOST = Pattern.compile("^[A-Za-z0-9._:\\[\\]-]+$");

    private SafeUrl() {
    }

    /**
     * Validate a request-derived url and return a new URL rebuilt from validated components.
     *
     * @param requested request-derived url
     * @return rebuilt http/https url whose host does not resolve to an internal address
     * @throws IOException if the url is illegal or points to an internal / blocked address (fail closed)
     */
    public static URL resolve(String requested) throws IOException {
        if (requested == null || requested.isEmpty()) {
            throw new IOException(SSRF_CHECK_FAILED);
        }

        // Strict hand-written parser: no URI/URL is created from the request-derived string.
        final UrlParts parts;
        try {
            parts = UrlParts.parse(requested);
        } catch (UrlParts.InvalidUrlException e) {
            throw new IOException(SSRF_CHECK_FAILED);
        }

        // The scheme of the rebuilt url is always one of the literals "http" / "https".
        final String scheme = parts.scheme();
        final String host = parts.host();
        if (host.isEmpty() || !SAFE_HOST.matcher(host).matches()) {
            throw new IOException(SSRF_CHECK_FAILED);
        }

        // Octal ip literals are parsed differently by different components: reject them.
        if (SSRFChecker.isOctalIP(host)) {
            throw new IOException(SSRF_CHECK_FAILED);
        }

        if (!ALLOWED_HOST_SUFFIXES.isEmpty()) {
            boolean allowed = false;
            for (String suffix : ALLOWED_HOST_SUFFIXES) {
                if (host.equals(suffix) || host.endsWith("." + suffix)) {
                    allowed = true;
                    break;
                }
            }
            if (!allowed) {
                throw new IOException(SSRF_CHECK_FAILED);
            }
        }

        final InetAddress[] addresses = InetAddress.getAllByName(host);
        if (addresses.length == 0) {
            throw new IOException(SSRF_CHECK_FAILED);
        }
        for (InetAddress address : addresses) {
            if (isBlocked(address)) {
                throw new IOException(SSRF_CHECK_FAILED);
            }
        }

        final int port = parts.port();
        if (port != -1 && (port < 1 || port > 65535)) {
            throw new IOException(SSRF_CHECK_FAILED);
        }

        return new URL(scheme, host, port, parts.pathAndQuery());
    }

    /**
     * Loopback, link-local (incl. cloud metadata 169.254.0.0/16), site-local, any-local, multicast,
     * unique-local ipv6 (fc00::/7, incl. fd00::/8), CGNAT, 0.0.0.0/8 and the configured blocked subnets.
     */
    private static boolean isBlocked(InetAddress address) {
        if (address.isAnyLocalAddress() || address.isLoopbackAddress() || address.isLinkLocalAddress()
                || address.isSiteLocalAddress() || address.isMulticastAddress()) {
            return true;
        }
        byte[] b = address.getAddress();
        if (b.length == 4) {
            int first = b[0] & 0xff;
            int second = b[1] & 0xff;
            if (first == 0 || (first == 100 && second >= 64 && second <= 127)) {
                return true;
            }
        } else if (b.length == 16 && (b[0] & 0xfe) == 0xfc) {
            return true;
        }
        if (b.length != 4) {
            // The configured blocklist only holds ipv4 subnets.
            return false;
        }
        try {
            // Configured blocklist. Any failure fails closed.
            return SSRFChecker.isInternalIp(address.getHostAddress());
        } catch (Exception e) {
            return true;
        }
    }
}
