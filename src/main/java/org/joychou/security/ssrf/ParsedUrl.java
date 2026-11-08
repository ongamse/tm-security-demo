package org.joychou.security.ssrf;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.regex.Pattern;

/**
 * Strict http(s) url parser. The untrusted string is split into components by hand and every
 * component is checked against a character whitelist, so only validated, server-constructed
 * values are used to build the outgoing {@link URI}. The raw string is never handed to
 * {@link URI} / {@link java.net.URL} constructors.
 *
 * <p>Rejected on purpose (fail closed): userinfo, IPv6 literals, backslashes, whitespace,
 * control characters, non-ascii hosts and anything other than http / https.</p>
 */
public final class ParsedUrl {

    private static final int MAX_URL_LENGTH = 2048;
    private static final Pattern HOST_PATTERN = Pattern.compile("^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$");
    private static final Pattern PATH_PATTERN = Pattern.compile("^(?:[A-Za-z0-9._~!$&'()*+,;=:@/-]|%[0-9A-Fa-f]{2})*$");
    private static final Pattern QUERY_PATTERN = Pattern.compile("^(?:[A-Za-z0-9._~!$&'()*+,;=:@/?-]|%[0-9A-Fa-f]{2})*$");

    /** "http" or "https" (constant, never copied from the input). */
    public final String scheme;
    /** Lower-cased host name or dotted ipv4 literal that matched the host whitelist. */
    public final String host;
    /** Port, or -1 when none was given. */
    public final int port;
    /** Validated absolute path, never empty. */
    public final String path;
    /** Validated query without the leading '?', or null. */
    public final String query;

    private ParsedUrl(String scheme, String host, int port, String path, String query) {
        this.scheme = scheme;
        this.host = host;
        this.port = port;
        this.path = path;
        this.query = query;
    }

    /**
     * Whether the given string is an acceptable host name / dotted ipv4 literal.
     */
    public static boolean isValidHost(String host) {
        return host != null && HOST_PATTERN.matcher(host).matches();
    }

    /**
     * Parse an absolute http(s) url.
     *
     * @param url untrusted url
     * @return parsed components, or null when the url is not acceptable
     */
    public static ParsedUrl parse(String url) {
        return parse(url, true);
    }

    /**
     * Extract only the validated, lower-cased host of an http(s) url (for allowlist comparison).
     * The path and query are not validated because they are never used.
     *
     * @param url untrusted url, e.g. a Referer or Origin header
     * @return host, or "" when the url or its authority is not acceptable
     */
    public static String hostOf(String url) {
        ParsedUrl parsed = parse(url, false);
        return parsed == null ? "" : parsed.host;
    }

    private static ParsedUrl parse(String url, boolean validateTail) {
        if (url == null || url.length() > MAX_URL_LENGTH) {
            return null;
        }
        String scheme;
        String rest;
        if (url.startsWith("http://")) {
            scheme = "http";
            rest = url.substring("http://".length());
        } else if (url.startsWith("https://")) {
            scheme = "https";
            rest = url.substring("https://".length());
        } else {
            return null;
        }

        // The fragment is never sent; drop it first so that '#' cannot hide a different authority.
        int fragment = rest.indexOf('#');
        if (fragment >= 0) {
            rest = rest.substring(0, fragment);
        }

        int authorityEnd = rest.length();
        for (int i = 0; i < rest.length(); i++) {
            char ch = rest.charAt(i);
            if (ch == '/' || ch == '?') {
                authorityEnd = i;
                break;
            }
        }
        String authority = rest.substring(0, authorityEnd);
        String tail = rest.substring(authorityEnd);

        String hostPart = authority;
        int port = -1;
        int colon = authority.lastIndexOf(':');
        if (colon >= 0) {
            hostPart = authority.substring(0, colon);
            String portPart = authority.substring(colon + 1);
            if (!portPart.isEmpty()) {
                if (portPart.length() > 5) {
                    return null;
                }
                for (int i = 0; i < portPart.length(); i++) {
                    char ch = portPart.charAt(i);
                    if (ch < '0' || ch > '9') {
                        return null;
                    }
                }
                port = Integer.parseInt(portPart);
                if (port < 1 || port > 65535) {
                    return null;
                }
            }
        }
        if (!isValidHost(hostPart)) {
            return null;
        }

        String path = tail;
        String query = null;
        int q = tail.indexOf('?');
        if (q >= 0) {
            path = tail.substring(0, q);
            query = tail.substring(q + 1);
        }
        if (path.isEmpty()) {
            path = "/";
        }
        if (validateTail) {
            if (!PATH_PATTERN.matcher(path).matches()) {
                return null;
            }
            if (query != null && !QUERY_PATTERN.matcher(query).matches()) {
                return null;
            }
        }
        return new ParsedUrl(scheme, hostPart.toLowerCase(java.util.Locale.ROOT), port, path, query);
    }

    /**
     * Build the outgoing URI from the validated components.
     */
    public URI toURI() throws URISyntaxException {
        StringBuilder sb = new StringBuilder();
        sb.append(scheme).append("://").append(host);
        if (port != -1) {
            sb.append(':').append(port);
        }
        sb.append(path);
        if (query != null) {
            sb.append('?').append(query);
        }
        return new URI(sb.toString());
    }
}
