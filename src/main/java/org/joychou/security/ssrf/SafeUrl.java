package org.joychou.security.ssrf;

import java.io.IOException;
import java.net.InetAddress;
import java.net.URL;
import java.net.UnknownHostException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The single choke point for every outgoing url of the application.
 *
 * <p>A user supplied string is parsed exactly once with a strict RFC 3986 subset (no user info,
 * no backslashes, no percent-encoded host, no control characters). The scheme must be http or
 * https, the host is resolved once and every resolved address must be public (loopback,
 * link-local incl. cloud metadata, site-local, any-local, multicast, unique-local and the
 * configured subnets are refused). The url that is requested is then <b>rebuilt</b> from the
 * validated components, never taken from the raw string. Redirects are never followed
 * automatically; {@link #resolve(String)} validates every hop with the same rules.</p>
 */
public final class SafeUrl {

    private static final String UNRESERVED_SUB_DELIMS = "A-Za-z0-9\\-._~!$&'()*+,;=:@%/";

    private static final Pattern URL_PATTERN = Pattern.compile(
            "([A-Za-z][A-Za-z0-9+.-]*)://"                    // 1 scheme
                    + "(\\[[0-9A-Fa-f:.]+\\]|[A-Za-z0-9.-]+)"            // 2 host (no user info)
                    + "(?::([0-9]{1,5}))?"                              // 3 port
                    + "(/[" + UNRESERVED_SUB_DELIMS + "]*)?"            // 4 path
                    + "(\\?[" + UNRESERVED_SUB_DELIMS + "?]*)?"         // 5 query
                    + "(#[" + UNRESERVED_SUB_DELIMS + "?]*)?");         // 6 fragment (dropped)

    private static final Pattern NUMERIC_HOST = Pattern.compile("[0-9.]+");
    private static final Pattern STRICT_IPV4 = Pattern.compile(
            "(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])");
    private static final Pattern HEX_LABEL = Pattern.compile("(?i)(^|\\.)0x[0-9a-f]*(\\.|$)");

    private static final Pattern ABSOLUTE_LOCATION = Pattern.compile("[A-Za-z][A-Za-z0-9+.-]*:.*", Pattern.DOTALL);

    private final String scheme;
    private final String host;
    private final int port;
    private final String path;
    private final String query;

    private SafeUrl(String scheme, String host, int port, String path, String query) {
        this.scheme = scheme;
        this.host = host;
        this.port = port;
        this.path = path;
        this.query = query;
    }


    /**
     * Strict syntax-only parse (no DNS, any scheme).
     *
     * @return the parsed components or null if the string is not a well formed absolute url
     */
    public static SafeUrl parseSyntax(String url) {
        if (url == null) {
            return null;
        }
        Matcher m = URL_PATTERN.matcher(url);
        if (!m.matches()) {
            return null;
        }
        int port = -1;
        if (m.group(3) != null) {
            port = Integer.parseInt(m.group(3));
            if (port < 1 || port > 65535) {
                return null;
            }
        }
        String host = m.group(2).toLowerCase(java.util.Locale.ROOT);
        if (host.startsWith(".") || host.endsWith("..") || host.contains("..")) {
            return null;
        }
        String path = m.group(4) == null ? "" : m.group(4);
        return new SafeUrl(m.group(1).toLowerCase(java.util.Locale.ROOT), host, port, path, m.group(5));
    }


    /**
     * Parse and validate an outgoing url: http/https only, public host only.
     *
     * @throws IOException if the url is not allowed
     */
    public static SafeUrl parse(String url) throws IOException {
        SafeUrl parsed = parseSyntax(url);
        if (parsed == null) {
            throw new IOException("[-] SSRF check failed. Illegal url");
        }
        if (!"http".equals(parsed.scheme) && !"https".equals(parsed.scheme)) {
            throw new IOException("[-] SSRF check failed. Illegal url protocol");
        }
        resolveExternal(parsed.host);
        return parsed;
    }


    /**
     * Resolve a host and refuse it if any of its addresses is internal.
     *
     * @param host host name, IPv4 literal or bracketed IPv6 literal
     * @return all (public) addresses of the host
     * @throws IOException if the host cannot be resolved or resolves to an internal address
     */
    public static InetAddress[] resolveExternal(String host) throws IOException {
        if (host == null || host.isEmpty()) {
            throw new IOException("[-] SSRF check failed. Illegal url host");
        }
        String name = host;
        if (name.length() > 2 && name.startsWith("[") && name.endsWith("]")) {
            name = name.substring(1, name.length() - 1);
        }
        // Numeric hosts must be canonical dotted decimal (or an IPv6 literal). Octal, hex, short
        // and integer forms are interpreted differently by resolvers and are refused.
        if (NUMERIC_HOST.matcher(name).matches() && !STRICT_IPV4.matcher(name).matches()) {
            throw new IOException("[-] SSRF check failed. Illegal url host");
        }
        if (HEX_LABEL.matcher(name).find()) {
            throw new IOException("[-] SSRF check failed. Illegal url host");
        }
        InetAddress[] addresses;
        try {
            addresses = InetAddress.getAllByName(name);
        } catch (UnknownHostException e) {
            throw new IOException("[-] SSRF check failed. Illegal url host");
        }
        for (InetAddress address : addresses) {
            if (SSRFChecker.isInternalIp(address.getHostAddress())) {
                throw new IOException("[-] SSRF check failed. Illegal url host");
            }
        }
        return addresses;
    }


    public String getScheme() {
        return scheme;
    }

    public String getHost() {
        return host;
    }

    public int getPort() {
        return port;
    }


    /**
     * Build the url that is requested from the validated components. The fragment is dropped.
     */
    public URL toURL() throws IOException {
        String protocol = "https".equals(scheme) ? "https" : "http";
        String file = (path.isEmpty() ? "/" : path) + (query == null ? "" : query);
        return new URL(protocol, host, port, file);
    }


    /**
     * Canonical string rebuilt from the validated components (fragment dropped). No DNS, no I/O.
     */
    public String toCanonicalString() {
        return scheme + "://" + host + (port >= 0 ? ":" + port : "") + path + (query == null ? "" : query);
    }


    public String toExternalForm() throws IOException {
        return toURL().toExternalForm();
    }


    /**
     * Resolve a redirect Location against this url and validate the result with the same rules.
     *
     * @throws IOException if the redirect target is not allowed
     */
    public SafeUrl resolve(String location) throws IOException {
        if (location == null || location.trim().isEmpty()) {
            throw new IOException("Redirect without Location header");
        }
        String loc = location.trim();
        String origin = scheme + "://" + host + (port >= 0 ? ":" + port : "");
        String candidate;
        if (ABSOLUTE_LOCATION.matcher(loc).matches()) {
            candidate = loc;
        } else if (loc.startsWith("//")) {
            candidate = scheme + ":" + loc;
        } else if (loc.startsWith("/")) {
            candidate = origin + loc;
        } else if (loc.startsWith("?")) {
            candidate = origin + (path.isEmpty() ? "/" : path) + loc;
        } else {
            int slash = path.lastIndexOf('/');
            String dir = slash < 0 ? "/" : path.substring(0, slash + 1);
            candidate = origin + dir + loc;
        }
        try {
            return parse(candidate);
        } catch (IOException e) {
            throw new IOException("[-] SSRF check failed. Illegal redirect url");
        }
    }
}
