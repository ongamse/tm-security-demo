package org.joychou.security.ssrf;

/**
 * Strict, hand-written parser for absolute http/https urls (no {@link java.net.URI} / {@link java.net.URL}
 * is ever created from the candidate string).
 *
 * <p>All components are rebuilt character by character from constant alphabets, so the exposed values are
 * freshly constructed strings and never the original request-derived string. Anything outside the strict
 * grammar (user info, ipv6 literals, backslashes, whitespace, control characters, bad percent escapes,
 * invalid ports, ...) is rejected with a constant-message {@link InvalidUrlException}. A fragment is dropped.</p>
 */
public final class UrlParts {

    /**
     * Thrown for any url that is not a strictly valid http/https url.
     */
    public static final class InvalidUrlException extends Exception {
        private static final long serialVersionUID = 1L;

        InvalidUrlException() {
            super("Invalid url");
        }
    }

    private static final int MAX_URL_LENGTH = 2048;
    private static final int MAX_HOST_LENGTH = 253;
    private static final int MAX_LABEL_LENGTH = 63;

    private static final String HOST_ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789.-";
    private static final String HEX_ALPHABET = "0123456789abcdefABCDEF";
    private static final String DIGIT_ALPHABET = "0123456789";
    /** RFC 3986 unreserved, sub-delims, '%' (validated separately), ':', '@' and '/'. */
    private static final String PATH_ALPHABET =
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~!$&'()*+,;=%:@/";
    /** Path alphabet plus '?' and the characters allowed in a query. */
    private static final String QUERY_ALPHABET = PATH_ALPHABET + "?";

    private final String scheme;
    private final String host;
    private final int port;
    private final String pathAndQuery;

    private UrlParts(String scheme, String host, int port, String pathAndQuery) {
        this.scheme = scheme;
        this.host = host;
        this.port = port;
        this.pathAndQuery = pathAndQuery;
    }

    /**
     * @return the literal "http" or "https"
     */
    public String scheme() {
        return scheme;
    }

    /**
     * @return lower-case host built from the alphabet [a-z0-9.-]
     */
    public String host() {
        return host;
    }

    /**
     * @return the port (1-65535) or -1 if absent
     */
    public int port() {
        return port;
    }

    /**
     * @return the path and the optional query, never empty (defaults to "/")
     */
    public String pathAndQuery() {
        return pathAndQuery;
    }

    /**
     * @return canonical url string assembled from the validated components
     */
    public String toCanonicalString() {
        StringBuilder sb = new StringBuilder(scheme).append("://").append(host);
        if (port != -1) {
            sb.append(':').append(port);
        }
        return sb.append(pathAndQuery).toString();
    }

    /**
     * Parse a candidate absolute http/https url.
     *
     * @param candidate request-derived string
     * @return the validated parts
     * @throws InvalidUrlException if the candidate is not a strictly valid http/https url
     */
    public static UrlParts parse(String candidate) throws InvalidUrlException {
        if (candidate == null || candidate.isEmpty() || candidate.length() > MAX_URL_LENGTH) {
            throw new InvalidUrlException();
        }

        // scheme
        final String scheme;
        final int afterScheme;
        if (candidate.regionMatches(true, 0, "http://", 0, 7)) {
            scheme = "http";
            afterScheme = 7;
        } else if (candidate.regionMatches(true, 0, "https://", 0, 8)) {
            scheme = "https";
            afterScheme = 8;
        } else {
            throw new InvalidUrlException();
        }

        // authority ends at the first '/', '?' or '#'
        int end = candidate.length();
        for (int i = afterScheme; i < candidate.length(); i++) {
            char c = candidate.charAt(i);
            if (c == '/' || c == '?' || c == '#') {
                end = i;
                break;
            }
        }

        // optional port: the only ':' of the authority (ipv6 literals are not supported)
        int colon = -1;
        for (int i = afterScheme; i < end; i++) {
            char c = candidate.charAt(i);
            if (c == '@') {
                // user info is never accepted
                throw new InvalidUrlException();
            }
            if (c == ':') {
                if (colon != -1) {
                    throw new InvalidUrlException();
                }
                colon = i;
            }
        }
        final int hostEnd = colon == -1 ? end : colon;

        final String host = buildHost(candidate, afterScheme, hostEnd);

        int port = -1;
        if (colon != -1) {
            port = parsePort(candidate, colon + 1, end);
        }

        // path and query (the fragment, if any, is dropped)
        int stop = candidate.length();
        for (int i = end; i < candidate.length(); i++) {
            if (candidate.charAt(i) == '#') {
                stop = i;
                break;
            }
        }
        final String pathAndQuery = buildPathAndQuery(candidate, end, stop);

        return new UrlParts(scheme, host, port, pathAndQuery);
    }

    private static String buildHost(String src, int from, int to) throws InvalidUrlException {
        if (to <= from || to - from > MAX_HOST_LENGTH) {
            throw new InvalidUrlException();
        }
        StringBuilder sb = new StringBuilder(to - from);
        int labelLength = 0;
        char previous = '.';
        for (int i = from; i < to; i++) {
            char c = src.charAt(i);
            if (c >= 'A' && c <= 'Z') {
                c = (char) (c + ('a' - 'A'));
            }
            int idx = HOST_ALPHABET.indexOf(c);
            if (idx < 0) {
                throw new InvalidUrlException();
            }
            char safe = HOST_ALPHABET.charAt(idx);
            if (safe == '.') {
                // empty labels and labels ending with '-' are not allowed
                if (labelLength == 0 || previous == '-') {
                    throw new InvalidUrlException();
                }
                labelLength = 0;
            } else {
                // labels must not start with '-'
                if (labelLength == 0 && safe == '-') {
                    throw new InvalidUrlException();
                }
                labelLength++;
                if (labelLength > MAX_LABEL_LENGTH) {
                    throw new InvalidUrlException();
                }
            }
            previous = safe;
            sb.append(safe);
        }
        // no trailing dot / trailing '-'
        if (labelLength == 0 || previous == '-') {
            throw new InvalidUrlException();
        }
        return sb.toString();
    }

    private static int parsePort(String src, int from, int to) throws InvalidUrlException {
        if (to <= from || to - from > 5) {
            throw new InvalidUrlException();
        }
        int value = 0;
        for (int i = from; i < to; i++) {
            int idx = DIGIT_ALPHABET.indexOf(src.charAt(i));
            if (idx < 0) {
                throw new InvalidUrlException();
            }
            value = value * 10 + idx;
        }
        if (value < 1 || value > 65535) {
            throw new InvalidUrlException();
        }
        return value;
    }

    private static String buildPathAndQuery(String src, int from, int to) throws InvalidUrlException {
        StringBuilder sb = new StringBuilder();
        boolean inQuery = false;
        for (int i = from; i < to; i++) {
            char c = src.charAt(i);
            if (!inQuery && c == '?') {
                if (sb.length() == 0) {
                    sb.append('/');
                }
                inQuery = true;
                sb.append('?');
                continue;
            }
            final String alphabet = inQuery ? QUERY_ALPHABET : PATH_ALPHABET;
            int idx = alphabet.indexOf(c);
            if (idx < 0) {
                throw new InvalidUrlException();
            }
            char safe = alphabet.charAt(idx);
            if (safe == '%') {
                // a percent sign must start a valid two digit hex escape
                if (i + 2 >= to) {
                    throw new InvalidUrlException();
                }
                if (HEX_ALPHABET.indexOf(src.charAt(i + 1)) < 0 || HEX_ALPHABET.indexOf(src.charAt(i + 2)) < 0) {
                    throw new InvalidUrlException();
                }
            }
            sb.append(safe);
        }
        if (sb.length() == 0) {
            sb.append('/');
        }
        return sb.toString();
    }
}
