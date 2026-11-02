package org.joychou.security;

import java.util.regex.Pattern;

/**
 * Immutable, strictly parsed absolute URL of the form <code>scheme://[userinfo@]host[:port][/path][?query][#fragment]</code>.
 * <p>
 * Untrusted text is parsed once with an explicit character allow-list and component grammar (RFC 3986
 * characters only, no backslash/whitespace/control characters, a single '@', numeric port, host name or
 * IP literal). No {@link java.net.URI} or {@link java.net.URL} object is built from the raw text, so every
 * later decision (allow-list, SSRF check, outbound request) works on the same normalised components.
 * Anything that does not parse is rejected (fail closed, {@link #parse(String)} returns null).
 */
public final class SafeUrl {

    private static final int MAX_LENGTH = 2048;

    private static final Pattern ALLOWED_CHARS = Pattern.compile("^[A-Za-z0-9\\-._~:/?#\\[\\]@!$&'()*+,;=%]+$");
    private static final Pattern SCHEME = Pattern.compile("^([A-Za-z][A-Za-z0-9+.\\-]*)://");
    private static final Pattern HOST_NAME = Pattern.compile(
            "^[A-Za-z0-9]([A-Za-z0-9\\-]*[A-Za-z0-9])?(\\.[A-Za-z0-9]([A-Za-z0-9\\-]*[A-Za-z0-9])?)*\\.?$");
    private static final Pattern IPV4 = Pattern.compile("^[0-9]{1,3}(\\.[0-9]{1,3}){3}$");
    private static final Pattern DIGITS_AND_DOTS = Pattern.compile("^[0-9.]+$");
    private static final Pattern IPV6 = Pattern.compile("^[0-9A-Fa-f:.]+$");
    private static final Pattern PORT = Pattern.compile("^[0-9]{1,5}$");

    private final String scheme;
    private final String userInfo;
    private final String host;
    private final int port;
    private final String rawPath;
    private final String rawQuery;
    private final String rawFragment;

    private SafeUrl(String scheme, String userInfo, String host, int port,
                    String rawPath, String rawQuery, String rawFragment) {
        this.scheme = scheme;
        this.userInfo = userInfo;
        this.host = host;
        this.port = port;
        this.rawPath = rawPath;
        this.rawQuery = rawQuery;
        this.rawFragment = rawFragment;
    }

    /**
     * Parse an absolute hierarchical URL.
     *
     * @param url untrusted text
     * @return the parsed url, or null when the text is not a well formed absolute url with a valid host
     */
    public static SafeUrl parse(String url) {
        if (url == null || url.isEmpty() || url.length() > MAX_LENGTH || !ALLOWED_CHARS.matcher(url).matches()) {
            return null;
        }
        if (!validPercentEncoding(url)) {
            return null;
        }

        java.util.regex.Matcher m = SCHEME.matcher(url);
        if (!m.find()) {
            return null;
        }
        String scheme = m.group(1).toLowerCase();
        String rest = url.substring(m.end());

        // split authority / path / query / fragment
        int authEnd = rest.length();
        for (int i = 0; i < rest.length(); i++) {
            char c = rest.charAt(i);
            if (c == '/' || c == '?' || c == '#') {
                authEnd = i;
                break;
            }
        }
        String authority = rest.substring(0, authEnd);
        String tail = rest.substring(authEnd);

        String fragment = null;
        int hash = tail.indexOf('#');
        if (hash >= 0) {
            fragment = tail.substring(hash + 1);
            tail = tail.substring(0, hash);
        }
        String query = null;
        int qm = tail.indexOf('?');
        if (qm >= 0) {
            query = tail.substring(qm + 1);
            tail = tail.substring(0, qm);
        }
        String path = tail;

        if (authority.isEmpty()) {
            return null;
        }

        // user info
        String userInfo = null;
        String hostPort = authority;
        int at = authority.indexOf('@');
        if (at >= 0) {
            if (at != authority.lastIndexOf('@')) {
                return null;
            }
            userInfo = authority.substring(0, at);
            hostPort = authority.substring(at + 1);
        }

        // host and port
        String host;
        String portText;
        if (hostPort.startsWith("[")) {
            int close = hostPort.indexOf(']');
            if (close < 0) {
                return null;
            }
            String literal = hostPort.substring(1, close);
            if (literal.indexOf(':') < 0 || !IPV6.matcher(literal).matches()) {
                return null;
            }
            host = "[" + literal.toLowerCase() + "]";
            String after = hostPort.substring(close + 1);
            if (after.isEmpty()) {
                portText = "";
            } else if (after.charAt(0) == ':') {
                portText = after.substring(1);
            } else {
                return null;
            }
        } else {
            int colon = hostPort.indexOf(':');
            String name = colon >= 0 ? hostPort.substring(0, colon) : hostPort;
            portText = colon >= 0 ? hostPort.substring(colon + 1) : "";
            if (!validHostName(name)) {
                return null;
            }
            host = name.toLowerCase();
        }

        int port = -1;
        if (!portText.isEmpty()) {
            if (!PORT.matcher(portText).matches()) {
                return null;
            }
            port = Integer.parseInt(portText);
            if (port > 65535) {
                return null;
            }
        }

        return new SafeUrl(scheme, userInfo, host, port, path, query, fragment);
    }

    private static boolean validPercentEncoding(String s) {
        for (int i = 0; i < s.length(); i++) {
            if (s.charAt(i) == '%') {
                if (i + 2 >= s.length() || !isHex(s.charAt(i + 1)) || !isHex(s.charAt(i + 2))) {
                    return false;
                }
                i += 2;
            }
        }
        return true;
    }

    private static boolean isHex(char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
    }

    private static boolean validHostName(String name) {
        if (name.isEmpty() || name.length() > 253) {
            return false;
        }
        if (DIGITS_AND_DOTS.matcher(name).matches()) {
            // numeric hosts must be a dotted quad with octets <= 255
            if (!IPV4.matcher(name).matches()) {
                return false;
            }
            for (String part : name.split("\\.")) {
                if (Integer.parseInt(part) > 255) {
                    return false;
                }
            }
            return true;
        }
        if (!HOST_NAME.matcher(name).matches()) {
            return false;
        }
        // the top level label must start with a letter
        String trimmed = name.endsWith(".") ? name.substring(0, name.length() - 1) : name;
        String top = trimmed.substring(trimmed.lastIndexOf('.') + 1);
        return !top.isEmpty() && Character.isLetter(top.charAt(0));
    }

    public String getScheme() {
        return scheme;
    }

    /** Raw user info or null. */
    public String getUserInfo() {
        return userInfo;
    }

    /** Lower case host name, dotted quad or bracketed IPv6 literal. */
    public String getHost() {
        return host;
    }

    /** Explicit port or -1 when absent. */
    public int getPort() {
        return port;
    }

    /** Raw path, never null (may be empty). */
    public String getRawPath() {
        return rawPath;
    }

    /** Raw query (without '?') or null when absent. */
    public String getRawQuery() {
        return rawQuery;
    }

    /** Raw fragment (without '#') or null when absent. */
    public String getRawFragment() {
        return rawFragment;
    }

    public boolean isHttp() {
        return "http".equals(scheme) || "https".equals(scheme);
    }

    /** Path and query as sent on the request line; the path is never empty. */
    public String getFile() {
        String p = rawPath.isEmpty() ? "/" : rawPath;
        return rawQuery == null ? p : p + "?" + rawQuery;
    }

    /** Origin (scheme://host[:port]) rebuilt from the validated components. */
    public String getOrigin() {
        return scheme + "://" + host + (port >= 0 ? ":" + port : "");
    }

    /**
     * Build a {@link java.net.URL} from the validated components (not from the original text).
     */
    public java.net.URL toURL() throws java.net.MalformedURLException {
        return new java.net.URL(scheme, host, port, getFile());
    }

    /** Rebuild the url (without user info and fragment) from the validated components only. */
    public String toExternalForm() {
        return getOrigin() + getFile();
    }
}
