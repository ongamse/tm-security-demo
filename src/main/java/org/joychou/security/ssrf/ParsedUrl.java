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

    // Trusted alphabets. Every output character is taken from one of these constants (never copied
    // from the input), so the components of the outgoing URI are server-constructed values.
    private static final String HOST_CHARS = "abcdefghijklmnopqrstuvwxyz0123456789.-";
    private static final String PATH_CHARS =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._~!$&'()*+,;=:@/-";
    private static final String QUERY_CHARS = PATH_CHARS + "?";
    private static final String HEX_UPPER = "0123456789ABCDEF";
    /** All printable ascii characters (0x20 - 0x7E), generated, never copied from input. */
    private static final String PRINTABLE = printableAscii();

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

        String rawPath = tail;
        String rawQuery = null;
        int q = tail.indexOf('?');
        if (q >= 0) {
            rawPath = tail.substring(0, q);
            rawQuery = tail.substring(q + 1);
        }
        if (rawPath.isEmpty()) {
            rawPath = "/";
        }
        String path = "/";
        String query = null;
        if (validateTail) {
            path = rebuild(rawPath, PATH_CHARS);
            if (path == null) {
                return null;
            }
            if (rawQuery != null) {
                query = rebuild(rawQuery, QUERY_CHARS);
                if (query == null) {
                    return null;
                }
            }
        }
        String host = rebuild(hostPart.toLowerCase(java.util.Locale.ROOT), HOST_CHARS);
        if (host == null) {
            return null;
        }
        return new ParsedUrl(scheme, host, port, path, query);
    }

    /**
     * Assemble a new string from the trusted alphabet. Each input character must be found in the
     * alphabet (the character that is appended is the alphabet's own) or be part of a well formed
     * percent escape (re-emitted with upper-case hex digits taken from {@link #HEX_UPPER}).
     * Encoded NUL and encoded '/' are refused so that escapes cannot change the path structure.
     *
     * @return the rebuilt value, or null if the value contains anything else
     */
    private static String rebuild(String value, String alphabet) {
        StringBuilder sb = new StringBuilder(value.length());
        for (int i = 0; i < value.length(); i++) {
            char ch = value.charAt(i);
            if (ch == '%') {
                if (i + 2 >= value.length()) {
                    return null;
                }
                int hi = hexValue(value.charAt(i + 1));
                int lo = hexValue(value.charAt(i + 2));
                if (hi < 0 || lo < 0) {
                    return null;
                }
                int octet = hi * 16 + lo;
                if (octet == 0x00 || octet == 0x2F) {
                    return null;
                }
                sb.append('%').append(HEX_UPPER.charAt(hi)).append(HEX_UPPER.charAt(lo));
                i += 2;
            } else {
                int idx = alphabet.indexOf(ch);
                if (idx < 0) {
                    return null;
                }
                sb.append(alphabet.charAt(idx));
            }
        }
        return sb.toString();
    }

    private static String printableAscii() {
        StringBuilder sb = new StringBuilder(95);
        for (int c = 0x20; c <= 0x7E; c++) {
            sb.append((char) c);
        }
        return sb.toString();
    }

    private static int hexValue(char ch) {
        if (ch >= '0' && ch <= '9') {
            return ch - '0';
        }
        if (ch >= 'a' && ch <= 'f') {
            return ch - 'a' + 10;
        }
        if (ch >= 'A' && ch <= 'F') {
            return ch - 'A' + 10;
        }
        return -1;
    }

    /**
     * Build the outgoing URI from the validated, server-assembled components with the
     * multi-argument {@link URI} constructor: constant scheme, alphabet-rebuilt host, int port and
     * path / query whose characters are all looked up in trusted tables (the constructor quotes
     * what must be quoted). No concatenated string is parsed.
     *
     * @throws URISyntaxException if a percent escape cannot be represented safely (fail closed)
     */
    public URI toURI() throws URISyntaxException {
        // scheme is one of the two constants assigned by parse(), never a copy of the input.
        String plainPath = decode(path, PATH_CHARS, false);
        String plainQuery = query == null ? null : decode(query, QUERY_CHARS, true);
        return new URI(scheme, null, host, port, plainPath, plainQuery, null);
    }

    /**
     * Turn the percent escapes of an already rebuilt component into characters taken from the
     * {@link #PRINTABLE} table (the {@link URI} constructor quotes them again where needed). All
     * other characters are looked up in the given alphabet. Escapes of non printable / non ascii
     * bytes are refused; in a query so are escapes of delimiter characters (they would change
     * its meaning once decoded).
     */
    private static String decode(String value, String alphabet, boolean query) throws URISyntaxException {
        StringBuilder sb = new StringBuilder(value.length());
        for (int i = 0; i < value.length(); i++) {
            char ch = value.charAt(i);
            if (ch != '%') {
                int idx = alphabet.indexOf(ch);
                if (idx < 0) {
                    throw new URISyntaxException("url", "illegal character");
                }
                sb.append(alphabet.charAt(idx));
                continue;
            }
            if (i + 2 >= value.length()) {
                throw new URISyntaxException("url", "illegal percent escape");
            }
            int octet = hexValue(value.charAt(i + 1)) * 16 + hexValue(value.charAt(i + 2));
            i += 2;
            if (octet < 0x20 || octet > 0x7E) {
                throw new URISyntaxException("url", "unsupported percent escape");
            }
            char decoded = PRINTABLE.charAt(octet - 0x20);
            boolean unreserved = (decoded >= 'A' && decoded <= 'Z') || (decoded >= 'a' && decoded <= 'z')
                    || (decoded >= '0' && decoded <= '9') || decoded == '-' || decoded == '.'
                    || decoded == '_' || decoded == '~';
            if (query && !unreserved && QUERY_CHARS.indexOf(decoded) >= 0) {
                throw new URISyntaxException("url", "unsupported percent escape");
            }
            sb.append(decoded);
        }
        return sb.toString();
    }
}
