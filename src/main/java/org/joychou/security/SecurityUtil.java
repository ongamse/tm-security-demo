package org.joychou.security;

import org.joychou.config.WebConfig;
import org.joychou.security.ssrf.PinnedSslSocketFactory;
import org.joychou.security.ssrf.SSRFChecker;
import org.joychou.security.ssrf.SocketHook;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.util.UriComponentsBuilder;

import javax.net.ssl.HttpsURLConnection;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;


public class SecurityUtil {

    private static final Pattern FILTER_PATTERN = Pattern.compile("^[a-zA-Z0-9_/\\.-]+$");
    private static final Set<String> ALLOWED_COMMANDS = new HashSet<String>(
            Arrays.asList("whoami", "id", "pwd", "uname", "ls", "uptime"));
    // Request value -> fixed server-side argv. The request value is only ever a lookup key.
    private static final Map<String, String[]> FIXED_COMMANDS = new HashMap<String, String[]>();
    // Request value -> fixed server-side directory constant.
    private static final Map<String, String> FIXED_DIRS = new HashMap<String, String>();
    static {
        FIXED_COMMANDS.put("whoami", new String[]{"whoami"});
        FIXED_COMMANDS.put("id", new String[]{"id"});
        FIXED_COMMANDS.put("pwd", new String[]{"pwd"});
        FIXED_COMMANDS.put("uname", new String[]{"uname"});
        FIXED_COMMANDS.put("uname -a", new String[]{"uname", "-a"});
        FIXED_COMMANDS.put("uptime", new String[]{"uptime"});
        FIXED_COMMANDS.put("ls", new String[]{"ls"});
        FIXED_COMMANDS.put("ls -la", new String[]{"ls", "-la"});

        FIXED_DIRS.put("/tmp", "/tmp");
        FIXED_DIRS.put("/var/log", "/var/log");
        FIXED_DIRS.put("/usr", "/usr");
        FIXED_DIRS.put(".", ".");
    }
    private static Logger logger = LoggerFactory.getLogger(SecurityUtil.class);


    /**
     * Map a request value to a fixed server-side argv (no user-derived elements).
     *
     * @param key request value, used only as a lookup key
     * @return a copy of the fixed argv, or null if the key is unknown
     */
    public static String[] fixedCommand(String key) {
        if (key == null) {
            return null;
        }
        String[] fixed = FIXED_COMMANDS.get(key.trim());
        return fixed == null ? null : fixed.clone();
    }


    /**
     * Map a request value to a fixed server-side directory constant.
     *
     * @param key request value, used only as a lookup key
     * @return the fixed directory, or null if the key is unknown
     */
    public static String fixedDir(String key) {
        if (key == null) {
            return null;
        }
        return FIXED_DIRS.get(key);
    }


    /**
     * Determine if the URL starts with HTTP.
     *
     * @param url url
     * @return true or false
     */
    public static boolean isHttp(String url) {
        return url.startsWith("http://") || url.startsWith("https://");
    }


    /**
     * Get http url host.
     *
     * @param url url
     * @return host
     */
    public static String gethost(String url) {
        UrlParts parts = parseUrl(url);
        return parts == null || parts.host == null ? "" : parts.host;
    }


    // Fixed alphabets. A URL string is never handed to java.net.URI/URL/InetAddress: it is parsed by
    // plain string code and every component is re-built character by character by indexing into one of
    // these constants (a char that is not in the alphabet rejects the whole url), so the values used by
    // the sinks below are server-owned strings.
    private static final String ALPHA_LOWER = "abcdefghijklmnopqrstuvwxyz";
    private static final String ALPHA_UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private static final String ALPHA_DIGITS = "0123456789";
    private static final String ALPHA_HEX = "0123456789abcdefABCDEF";
    private static final String ALPHA_SCHEME = ALPHA_LOWER + ALPHA_UPPER + ALPHA_DIGITS + "+-.";
    private static final String ALPHA_HOST = ALPHA_LOWER + ALPHA_UPPER + ALPHA_DIGITS + "-.";
    private static final String ALPHA_IPV6 = "[]" + ALPHA_DIGITS + "abcdefABCDEF:.";
    // unreserved + the sub-delims, ':' '@' (pchar) and '/' '?'; '%' is handled separately (needs two hex digits).
    private static final String ALPHA_COMPONENT = ALPHA_LOWER + ALPHA_UPPER + ALPHA_DIGITS + "-._~!$&'()*+,;=:@/?";


    /**
     * The parts of a url, each re-built from a fixed alphabet (see above). Never null-safe to use
     * unchecked: host is null when the authority is missing or not a strictly valid host.
     */
    private static final class UrlParts {
        String scheme;        // lower case, null when the reference has no scheme
        boolean hasAuthority;
        boolean userInfo;
        String host;          // lower case canonical host (IPv6 in brackets), null when absent or invalid
        int port = -1;        // -1 when absent
        String path = "";
        String query;         // null when absent
        String fragment;      // null when absent
    }


    private static String rebuild(String s, String alphabet) {
        StringBuilder sb = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            int idx = alphabet.indexOf(s.charAt(i));
            if (idx < 0) {
                return null;
            }
            sb.append(alphabet.charAt(idx));
        }
        return sb.toString();
    }


    /** Re-build a path / query / fragment: whitelist chars and well formed %XX escapes only. */
    private static String rebuildComponent(String s) {
        StringBuilder sb = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '%') {
                if (i + 2 >= s.length()) {
                    return null;
                }
                int h1 = ALPHA_HEX.indexOf(s.charAt(i + 1));
                int h2 = ALPHA_HEX.indexOf(s.charAt(i + 2));
                if (h1 < 0 || h2 < 0) {
                    return null;
                }
                sb.append('%').append(ALPHA_HEX.charAt(h1)).append(ALPHA_HEX.charAt(h2));
                i += 2;
                continue;
            }
            int idx = ALPHA_COMPONENT.indexOf(c);
            if (idx < 0) {
                return null;
            }
            sb.append(ALPHA_COMPONENT.charAt(idx));
        }
        return sb.toString();
    }


    /**
     * Pure string parser for an RFC 3986 reference (scheme, authority, path, query, fragment). Rejects
     * (returns null) anything outside the whitelist alphabets: control characters, spaces, backslashes,
     * non ASCII, unwise characters, malformed %-escapes, more than one '@', a bad port.
     */
    private static UrlParts parseUrl(String url) {
        if (url == null || url.isEmpty() || url.length() > 8192) {
            return null;
        }
        UrlParts p = new UrlParts();
        String rest = url;

        int delim = -1;
        for (int i = 0; i < url.length(); i++) {
            char c = url.charAt(i);
            if (c == ':' || c == '/' || c == '?' || c == '#') {
                delim = i;
                break;
            }
        }
        if (delim >= 0 && url.charAt(delim) == ':') {
            String scheme = delim == 0 ? null : rebuild(url.substring(0, delim), ALPHA_SCHEME);
            if (scheme == null || ALPHA_LOWER.indexOf(Character.toLowerCase(scheme.charAt(0))) < 0) {
                return null;
            }
            p.scheme = scheme.toLowerCase(Locale.ROOT);
            rest = url.substring(delim + 1);
        }

        int hash = rest.indexOf('#');
        String fragment = null;
        if (hash >= 0) {
            fragment = rest.substring(hash + 1);
            rest = rest.substring(0, hash);
            if (fragment.indexOf('#') >= 0) {
                return null;
            }
        }
        int qm = rest.indexOf('?');
        String query = null;
        if (qm >= 0) {
            query = rest.substring(qm + 1);
            rest = rest.substring(0, qm);
        }

        String authority = null;
        if (rest.startsWith("//")) {
            int slash = rest.indexOf('/', 2);
            authority = slash < 0 ? rest.substring(2) : rest.substring(2, slash);
            rest = slash < 0 ? "" : rest.substring(slash);
        }

        String path = rebuildComponent(rest);
        if (path == null) {
            return null;
        }
        p.path = path;
        if (query != null) {
            p.query = rebuildComponent(query);
            if (p.query == null) {
                return null;
            }
        }
        if (fragment != null) {
            p.fragment = rebuildComponent(fragment);
            if (p.fragment == null) {
                return null;
            }
        }

        if (authority != null) {
            p.hasAuthority = true;
            parseAuthority(authority, p);
        }
        return p;
    }


    /** Fills host / port / userInfo; leaves host null when the authority is not a valid server authority. */
    private static void parseAuthority(String authority, UrlParts p) {
        String hostPort = authority;
        int at = authority.indexOf('@');
        if (at >= 0) {
            if (at != authority.lastIndexOf('@')) {
                return;
            }
            p.userInfo = true;
            if (rebuildComponent(authority.substring(0, at)) == null) {
                return;
            }
            hostPort = authority.substring(at + 1);
        }

        String rawHost;
        String rawPort = "";
        if (hostPort.startsWith("[")) {
            int end = hostPort.indexOf(']');
            if (end < 0) {
                return;
            }
            rawHost = hostPort.substring(0, end + 1);
            String after = hostPort.substring(end + 1);
            if (!after.isEmpty()) {
                if (after.charAt(0) != ':') {
                    return;
                }
                rawPort = after.substring(1);
            }
        } else {
            int colon = hostPort.lastIndexOf(':');
            rawHost = colon < 0 ? hostPort : hostPort.substring(0, colon);
            rawPort = colon < 0 ? "" : hostPort.substring(colon + 1);
        }

        String cleanPort = rebuild(rawPort, ALPHA_DIGITS);
        if (cleanPort == null || cleanPort.length() > 9) {
            return;
        }
        int port = cleanPort.isEmpty() ? -1 : Integer.parseInt(cleanPort);

        String cleanHost = rebuild(rawHost, rawHost.startsWith("[") ? ALPHA_IPV6 : ALPHA_HOST);
        p.host = cleanHost == null ? null : canonicalHost(cleanHost);
        p.port = port;
    }


    /**
     * 同时支持一级域名和多级域名，相关配置在resources目录下url/url_safe_domain.xml文件。
     * 优先判断黑名单，如果满足黑名单return null。
     *
     * @param url the url need to check
     * @return Safe url returns original url; Illegal url returns null;
     */
    public static String checkURL(String url) {

        if (null == url){
            return null;
        }

        ArrayList<String> safeDomains = WebConfig.getSafeDomains();
        ArrayList<String> blockDomains = WebConfig.getBlockDomains();

        try {
            String host = gethost(url);

            // 必须http/https
            if (!isHttp(url)) {
                return null;
            }

            // 如果满足黑名单返回null
            if (blockDomains.contains(host)){
                return null;
            }
            for(String blockDomain: blockDomains) {
                if(host.endsWith("." + blockDomain)) {
                    return null;
                }
            }

            // 支持多级域名
            if (safeDomains.contains(host)){
                return url;
            }

            // 支持一级域名
            for(String safedomain: safeDomains) {
                if(host.endsWith("." + safedomain)) {
                    return url;
                }
            }
            return null;
        } catch (NullPointerException e) {
            logger.error(e.toString());
            return null;
        }
    }


    /**
     * Validate a redirect destination. Only relative same-site paths (single leading slash) or
     * absolute http/https urls whose host passes {@link #checkURL(String)} are accepted.
     * Scheme-relative urls (//host), backslashes, control characters, other schemes and
     * encoded variants of those are rejected.
     *
     * @param url the redirect target supplied by the client
     * @return the original url if it is safe to redirect to; otherwise null
     */
    public static String checkRedirectURL(String url) {
        if (url == null || url.isEmpty()) {
            return null;
        }

        // Check the raw value and its decoded form (also decode twice to catch double encoding).
        String decoded = url;
        for (int i = 0; i < 2; i++) {
            if (!isPlainRedirectString(decoded)) {
                return null;
            }
            try {
                decoded = URLDecoder.decode(decoded, "UTF-8");
            } catch (UnsupportedEncodingException | IllegalArgumentException e) {
                return null;
            }
        }
        if (!isPlainRedirectString(decoded)) {
            return null;
        }

        try {
            // Pure string parse; every component is re-built from a fixed alphabet (see parseUrl).
            UrlParts uri = parseUrl(url);
            if (uri == null) {
                return null;
            }
            String rawPath = uri.path;

            if (uri.scheme == null) {
                // Same-site path only: single leading slash, no authority, never "//host" or "/\host".
                if (uri.hasAuthority || !rawPath.startsWith("/")
                        || rawPath.startsWith("//") || decoded.startsWith("//")) {
                    return null;
                }
                // Re-built from the validated path/query components, not the request string.
                return UriComponentsBuilder.newInstance()
                        .path(rawPath)
                        .query(uri.query)
                        .fragment(uri.fragment)
                        .build(true)
                        .toUriString();
            }

            String scheme = uri.scheme;
            if (!"http".equals(scheme) && !"https".equals(scheme)) {
                return null;
            }
            if (uri.userInfo) {
                return null;
            }
            int port = uri.port;
            if (port != -1 && (port < 1 || port > 65535)) {
                return null;
            }
            String host = uri.host;
            if (host == null) {
                return null;
            }
            String safeHost = allowedRedirectHost(host);
            if (safeHost == null) {
                return null;
            }
            // Re-built from the allowlist host and the validated URI components.
            return UriComponentsBuilder.newInstance()
                    .scheme("https".equals(scheme) ? "https" : "http")
                    .host(safeHost)
                    .port(port)
                    .path(rawPath)
                    .query(uri.query)
                    .fragment(uri.fragment)
                    .build(true)
                    .toUriString();
        } catch (IllegalArgumentException e) {
            return null;
        }
    }


    /**
     * Look the host up in the configured safe/block domain lists (url_safe_domain.xml).
     *
     * @param host validated lower case host
     * @return the configured allowlist entry when the host equals it, the validated host when it is a
     *         sub domain of an entry, or null when it is blocked or not allowlisted
     */
    private static String allowedRedirectHost(String host) {
        ArrayList<String> safeDomains = WebConfig.getSafeDomains();
        ArrayList<String> blockDomains = WebConfig.getBlockDomains();

        for (String blockDomain : blockDomains) {
            if (host.equals(blockDomain) || host.endsWith("." + blockDomain)) {
                return null;
            }
        }
        for (String safeDomain : safeDomains) {
            if (host.equals(safeDomain)) {
                return safeDomain;
            }
        }
        for (String safeDomain : safeDomains) {
            if (host.endsWith("." + safeDomain)) {
                return host;
            }
        }
        return null;
    }


    private static boolean isPlainRedirectString(String s) {
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '\\' || c <= 0x20 || c == 0x7f) {
                return false;
            }
        }
        return true;
    }


    /**
     * 通过自定义白名单域名处理SSRF漏洞。如果URL范围收敛，强烈建议使用该方案。
     * 这是最简单也最有效的修复方式。因为SSRF都是发起URL请求时造成，大多数场景是图片场景，一般图片的域名都是CDN或者OSS等，所以限定域名白名单即可完成SSRF漏洞修复。
     *
     * @author JoyChou @ 2020-03-30
     * @param url 需要校验的url
     * @return Safe url returns true. Dangerous url returns false.
     */
    public static boolean checkSSRFByWhitehosts(String url) {
        return SSRFChecker.checkURLFckSSRF(url);
    }


    /**
     * 解析URL的IP，判断IP是否是内网IP。如果有重定向跳转，循环解析重定向跳转的IP。不建议使用该方案。
     *
     * 存在的问题：
     *   1、会主动发起请求，可能会有性能问题
     *   2、设置重定向跳转为第一次302不跳转，第二次302跳转到内网IP 即可绕过该防御方案
     *   3、TTL设置为0会被绕过
     *
     * @param url check的url
     * @return 安全返回true，危险返回false
     */
    @Deprecated
    public static boolean checkSSRF(String url) {
        int checkTimes = 10;
        return SSRFChecker.checkSSRF(url, checkTimes);
    }


    /**
     * 不能使用白名单的情况下建议使用该方案。前提是禁用重定向并且TTL默认不为0。
     *
     * 存在问题：
     *  1、TTL为0会被绕过
     *  2、使用重定向可绕过
     *
     * @param url The url that needs to check.
     * @return Safe url returns true. Dangerous url returns false.
     */
    public static boolean checkSSRFWithoutRedirect(String url) {
        if(url == null) {
            return false;
        }
        return !SSRFChecker.isInternalIpByUrl(url);
    }

    /**
     * Validate an outbound request URL: only http/https, a parseable host, and every address
     * the host resolves to must be public (not loopback, link-local/metadata, site-local,
     * unique-local, multicast, wildcard, or inside the configured blocked subnets).
     * Fails closed. Redirects must be validated again by the caller on every hop.
     *
     * @param url The url that needs to check.
     * @return Safe url returns true. Dangerous url returns false.
     */
    public static boolean checkSSRFResolved(String url) {
        try {
            safeTarget(url);
            return true;
        } catch (IOException e) {
            logger.error("SSRF check failed: " + e.toString());
            return false;
        }
    }


    // Host name: dot separated LDH labels. Anything else (userinfo, %-escapes, backslash, unicode...) is rejected.
    private static final Pattern HOST_PATTERN = Pattern.compile(
            "^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$");
    private static final Pattern NUMERIC_HOST = Pattern.compile("^[0-9.]+$");
    // Only canonical dotted-quad IPv4 (no octal / hex / short forms that parsers read differently).
    private static final Pattern STRICT_IPV4 = Pattern.compile(
            "^(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])$");
    private static final Pattern IPV6_LITERAL = Pattern.compile("^\\[[0-9a-f:.]{2,45}\\]$");


    /**
     * A validated outbound destination. Every component was re-built from the parsed and validated
     * pieces of the user url, and the resolved address is pinned so the connection cannot be
     * re-resolved (DNS rebinding) to another address after validation.
     */
    public static final class SafeTarget {
        private final String scheme;
        private final String host;
        private final int port;
        private final String file;
        private final InetAddress[] addresses;
        private final InetAddress address;
        private final String hostHeader;

        private SafeTarget(String scheme, String host, int port, String file, InetAddress[] addresses,
                           String hostHeader) {
            this.scheme = scheme;
            this.host = host;
            this.port = port;
            this.file = file;
            this.hostHeader = hostHeader;
            this.addresses = addresses.clone();
            this.address = addresses[0];
        }

        /** All validated addresses of the host (every one of them is public). */
        public InetAddress[] getAddresses() {
            return addresses.clone();
        }

        public boolean isHttps() {
            return "https".equals(scheme);
        }

        /** Validated canonical (lower case) host of the original url. */
        public String getHost() {
            return host;
        }

        public InetAddress getAddress() {
            return address;
        }

        public String getScheme() {
            return scheme;
        }

        /** Explicit port, or -1 for the scheme default. */
        public int getPort() {
            return port;
        }

        /** Validated path and query (always starts with a slash). */
        public String getFile() {
            return file;
        }

        /** The pinned literal IP, bracketed for IPv6, as used in {@link #getUrl()}. */
        public String getPinnedHost() {
            String ip = address.getHostAddress();
            if (address instanceof Inet6Address) {
                int scope = ip.indexOf('%');
                return "[" + (scope >= 0 ? ip.substring(0, scope) : ip) + "]";
            }
            return ip;
        }

        /** Value for the Host header when connecting to the pinned IP. */
        public String getHostHeader() {
            return hostHeader;
        }

        /** Url that connects to the pinned literal IP (scheme, ip, port, path and query only). */
        public URL getUrl() throws MalformedURLException {
            return new URL(scheme, getPinnedHost(), port, file);
        }

        /** Url re-built from the validated canonical host name (for clients that pin the address themselves). */
        public URL getCanonicalUrl() throws MalformedURLException {
            return new URL(scheme, host, port, file);
        }

        /**
         * Url for third-party http clients that cannot pin the address. http targets use the pinned IP
         * (the client derives the Host header from the url). https targets keep the validated host name so
         * the TLS certificate can be verified by the client; redirects must stay disabled.
         */
        public URL getClientUrl() throws MalformedURLException {
            return isHttps() ? getCanonicalUrl() : getUrl();
        }
    }


    private static boolean isHttpAllowed() {
        String v = System.getProperty("ssrf.allow.http");
        if (v == null) {
            v = System.getenv("SSRF_ALLOW_HTTP");
        }
        return v == null || Boolean.parseBoolean(v.trim());
    }


    private static String canonicalHost(String host) {
        if (host == null || host.isEmpty() || host.length() > 253) {
            return null;
        }
        String h = host.toLowerCase(Locale.ROOT);
        // Valid hosts are returned re-built from the fixed host alphabets, not as the input string.
        if (h.startsWith("[")) {
            return IPV6_LITERAL.matcher(h).matches() ? rebuild(h, ALPHA_IPV6) : null;
        }
        if (NUMERIC_HOST.matcher(h).matches()) {
            return STRICT_IPV4.matcher(h).matches() ? rebuild(h, ALPHA_HOST) : null;
        }
        return HOST_PATTERN.matcher(h).matches() ? rebuild(h, ALPHA_HOST) : null;
    }


    public static boolean isPublicAddress(InetAddress addr) {
        if (addr.isAnyLocalAddress() || addr.isLoopbackAddress() || addr.isLinkLocalAddress()
                || addr.isSiteLocalAddress() || addr.isMulticastAddress()) {
            return false; // also covers cloud metadata 169.254.169.254
        }
        if (addr instanceof Inet6Address && (addr.getAddress()[0] & 0xfe) == 0xfc) {
            return false; // unique local fc00::/7
        }
        return !(addr instanceof Inet4Address && SSRFChecker.isInternalIp(addr.getHostAddress()));
    }


    /**
     * The single SSRF gate for outbound requests. Parses the user url with a pure string parser (see parseUrl), requires
     * http/https (https only when <code>-Dssrf.allow.http=false</code> or env <code>SSRF_ALLOW_HTTP=false</code>),
     * no userinfo, a strictly valid host, resolves every A/AAAA address and rejects loopback,
     * link-local (cloud metadata), site-local, unique-local, multicast, wildcard and configured
     * blocked subnets. The returned target is re-built from the validated components and pins
     * the resolved address. Fails closed.
     *
     * @param url user supplied url
     * @return the validated target
     * @throws IOException if the url is not allowed
     */
    public static SafeTarget safeTarget(String url) throws IOException {
        if (url == null) {
            throw new IOException("[-] SSRF check failed. Illegal url.");
        }
        try {
            // Pure string parse; scheme/host/port/path/query are re-built from fixed alphabets (parseUrl),
            // so nothing below hands the request string itself to java.net.
            UrlParts uri = parseUrl(url);
            if (uri == null) {
                throw new IOException("[-] SSRF check failed. Illegal url.");
            }
            String scheme = uri.scheme == null ? "" : uri.scheme;
            boolean https = "https".equals(scheme);
            if (!https && !("http".equals(scheme) && isHttpAllowed())) {
                throw new IOException("[-] SSRF check failed. Illegal scheme.");
            }
            if (!uri.hasAuthority || uri.userInfo) {
                throw new IOException("[-] SSRF check failed. Userinfo not allowed.");
            }
            String host = uri.host;
            if (host == null) {
                throw new IOException("[-] SSRF check failed. Illegal host.");
            }
            int port = uri.port;
            if (port != -1 && (port < 1 || port > 65535)) {
                throw new IOException("[-] SSRF check failed. Illegal port.");
            }

            InetAddress[] addrs = InetAddress.getAllByName(host);
            if (addrs.length == 0) {
                throw new IOException("[-] SSRF check failed. Unresolvable host.");
            }
            for (InetAddress addr : addrs) {
                if (!isPublicAddress(addr)) {
                    throw new IOException("[-] SSRF check failed. Internal address.");
                }
            }

            String file = uri.path.isEmpty() ? "/" : uri.path;
            if (!file.startsWith("/")) {
                throw new IOException("[-] SSRF check failed. Illegal path.");
            }
            if (uri.query != null) {
                file = file + "?" + uri.query;
            }
            // Host header value: an IPv6 literal comes from the resolved address, a host name is
            // URL-encoded (a no-op for valid LDH labels, but CR/LF can never survive) and the port is an int.
            boolean defaultPort = port == -1 || (port == 80 && !https) || (port == 443 && https);
            String hostPart;
            if (host.startsWith("[")) {
                String ip = addrs[0].getHostAddress();
                int scope = ip.indexOf('%');
                hostPart = "[" + (scope >= 0 ? ip.substring(0, scope) : ip) + "]";
            } else {
                try {
                    hostPart = URLEncoder.encode(host, "UTF-8");
                } catch (UnsupportedEncodingException e) {
                    throw new IOException("[-] SSRF check failed. Illegal host.");
                }
            }
            String hostHeader = defaultPort ? hostPart : hostPart + ":" + Integer.toString(port);
            return new SafeTarget(https ? "https" : "http", host, port, file, addrs, hostHeader);
        } catch (UnknownHostException e) {
            throw new IOException("[-] SSRF check failed. " + e.getClass().getSimpleName());
        }
    }


    /**
     * Convenience wrapper over {@link #safeTarget(String)}.
     *
     * @return the re-built url (pinned literal IP) for the validated user url
     * @throws IOException if the url is not allowed
     */
    public static URL safeUrl(String url) throws IOException {
        return safeTarget(url).getUrl();
    }


    /**
     * Open an unconnected HttpURLConnection for a validated target. Redirects are disabled (each hop
     * must be passed through {@link #safeTarget(String)} again by the caller).
     * <ul>
     *   <li>https: the url is re-built from the validated canonical host; the TLS socket factory
     *       re-checks the address that was actually connected to (DNS rebinding) before any byte is
     *       sent, and the certificate is verified against the host name as usual.</li>
     *   <li>http: the url is re-built with the pinned literal IP and the JDK derives the Host header from
     *       it, so name based virtual hosting is not available over plain http; set
     *       <code>SSRF_ALLOW_HTTP=false</code> to allow https only.</li>
     * </ul>
     */
    public static HttpURLConnection openConnection(SafeTarget target) throws IOException {
        HttpURLConnection conn = (HttpURLConnection) (target.isHttps() ? target.getCanonicalUrl() : target.getUrl())
                .openConnection();
        conn.setInstanceFollowRedirects(false);
        if (conn instanceof HttpsURLConnection) {
            ((HttpsURLConnection) conn).setSSLSocketFactory(new PinnedSslSocketFactory());
        }
        return conn;
    }


    /**
     * Check ssrf by hook socket. Start socket hook.
     *
     * @author liergou @ 2020-04-04 02:15
     */
    public static void startSSRFHook() throws IOException {
        SocketHook.startHook();
    }

    /**
     * Close socket hook.
     *
     * @author liergou @ 2020-04-04 02:15
     **/
    public static void stopSSRFHook(){
        SocketHook.stopHook();
    }



    /**
     * Filter file path to prevent path traversal vulns.
     *
     * @param filepath file path
     * @return illegal file path return null
     */
    public static String pathFilter(String filepath) {
        String temp = filepath;

        // use while to sovle multi urlencode
        while (temp.indexOf('%') != -1) {
            try {
                temp = URLDecoder.decode(temp, "utf-8");
            } catch (UnsupportedEncodingException e) {
                logger.info("Unsupported encoding exception: " + filepath);
                return null;
            } catch (Exception e) {
                logger.info(e.toString());
                return null;
            }
        }

        if (temp.contains("..") || temp.charAt(0) == '/') {
            return null;
        }

        return filepath;
    }


    public static String cmdFilter(String input) {
        if (!FILTER_PATTERN.matcher(input).matches()) {
            return null;
        }

        return input;
    }


    /**
     * Remove CR, LF and all other ISO control characters from a value that is written into
     * an HTTP response header, so attacker-controlled data cannot split the response
     * (CRLF / header injection).
     *
     * @param value header value, may be null
     * @return the value without control characters, or null if value is null
     */
    public static String headerValueFilter(String value) {
        if (value == null) {
            return null;
        }
        StringBuilder sb = new StringBuilder(value.length());
        for (int i = 0; i < value.length(); i++) {
            char ch = value.charAt(i);
            int type = Character.getType(ch);
            // drops CR, LF, NUL and other ISO controls plus Unicode line/paragraph separators
            if (!Character.isISOControl(ch) && type != Character.LINE_SEPARATOR
                    && type != Character.PARAGRAPH_SEPARATOR) {
                sb.append(ch);
            }
        }
        return sb.toString();
    }


    // RFC 3986 reserved characters (and '%') that stay readable after URL-encoding a header value.
    private static final String HEADER_RESTORE_CHARS = ":/?#[]@!$&'()*,;=%";


    /**
     * Strictly validate a value that will be written to an HTTP response header and return a value
     * that is re-built character by character from a fixed whitelist. The raw value must match the
     * whitelist, and neither it nor its (repeatedly) url decoded form may contain CR, LF or any
     * other control character, so encoded line breaks (%0d, %0a, %250d ...) are rejected too.
     * Fails closed: nothing is written when the value is not acceptable.
     *
     * @param value untrusted header value, may be null
     * @return the re-built value, or null if the value is null or not acceptable
     */
    public static String safeHeaderValue(String value) {
        if (value == null || value.length() > 2048) {
            return null;
        }
        String decoded = value;
        for (int i = 0; i < 4 && decoded.indexOf('%') != -1; i++) {
            try {
                decoded = URLDecoder.decode(decoded, "UTF-8");
            } catch (UnsupportedEncodingException | IllegalArgumentException e) {
                return null;
            }
            if (hasLineBreakOrControl(decoded)) {
                return null;
            }
        }
        if (hasLineBreakOrControl(decoded)) {
            return null;
        }
        // URL-encode the value (CR/LF/control chars and everything outside the unreserved set become %XX),
        // then restore only the RFC 3986 reserved characters that are legal in a URL / file name header value.
        String encoded;
        try {
            encoded = URLEncoder.encode(value, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            return null;
        }
        encoded = encoded.replace("+", "%20");
        for (int i = 0; i < HEADER_RESTORE_CHARS.length(); i++) {
            char c = HEADER_RESTORE_CHARS.charAt(i);
            // '%' is restored last (existing %XX escapes stay as they were); a raw CR/LF/control char
            // is never restored because it is not in HEADER_RESTORE_CHARS.
            encoded = encoded.replace(String.format("%%%02X", (int) c), String.valueOf(c));
        }
        return encoded;
    }


    private static boolean hasLineBreakOrControl(String s) {
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            int type = Character.getType(c);
            if (Character.isISOControl(c) || type == Character.LINE_SEPARATOR
                    || type == Character.PARAGRAPH_SEPARATOR) {
                return true;
            }
        }
        return false;
    }


    /**
     * Map a request Origin to the value allowed in Access-Control-Allow-Origin. The lower cased request
     * Origin is only a lookup key in a fixed server-side map (http/https x configured safe domain from
     * url_safe_domain.xml, minus the block list, with the default port or 8080/8443); the returned
     * String is the map's constant value, never a string derived from the request.
     *
     * @param origin the Origin request header value, may be null
     * @return the origin to reflect, or null when no CORS header should be written
     */
    public static String corsOrigin(String origin) {
        if (origin == null || origin.isEmpty() || origin.length() > 2048) {
            return null;
        }
        // The request value is only a lookup key; the returned String is a server-owned constant.
        return currentCorsOrigins().get(origin.toLowerCase(Locale.ROOT));
    }


    // Ports (besides the scheme default) that are allowed for the configured safe domains.
    private static final int[] CORS_EXTRA_PORTS = {8080, 8443};
    private static volatile ArrayList<String> corsSafeDomainsSource;
    private static volatile ArrayList<String> corsBlockDomainsSource;
    private static volatile Map<String, String> corsOriginMap = new HashMap<String, String>();


    /**
     * Fixed allowlist of origins (lower case key -> constant value) built from the configured safe
     * domains (url_safe_domain.xml) minus the block list. Rebuilt only when the configuration changes.
     */
    private static Map<String, String> currentCorsOrigins() {
        ArrayList<String> safe = WebConfig.getSafeDomains();
        ArrayList<String> block = WebConfig.getBlockDomains();
        if (safe != corsSafeDomainsSource || block != corsBlockDomainsSource) {
            synchronized (SecurityUtil.class) {
                if (safe != corsSafeDomainsSource || block != corsBlockDomainsSource) {
                    Map<String, String> map = new HashMap<String, String>();
                    for (String domain : safe) {
                        if (domain == null || canonicalHost(domain) == null) {
                            continue;
                        }
                        boolean blocked = false;
                        for (String b : block) {
                            if (domain.equals(b) || domain.endsWith("." + b)) {
                                blocked = true;
                                break;
                            }
                        }
                        if (blocked) {
                            continue;
                        }
                        String d = domain.toLowerCase(Locale.ROOT);
                        for (String sch : new String[]{"http", "https"}) {
                            String base = sch + "://" + d;
                            map.put(base, base);
                            for (int p : CORS_EXTRA_PORTS) {
                                String withPort = base + ":" + p;
                                map.put(withPort, withPort);
                            }
                        }
                    }
                    corsOriginMap = map;
                    corsSafeDomainsSource = safe;
                    corsBlockDomainsSource = block;
                }
            }
        }
        return corsOriginMap;
    }


    /**
     * Parse a user supplied command line into an argv array for a no-shell process API.
     * The executable must be in a small allowlist and every argument must match the
     * same strict character set as {@link #cmdFilter(String)}.
     *
     * @param cmdLine whitespace separated command line, e.g. "ls -la /tmp"
     * @return argv array, or null if the command or any argument is not allowed
     */
    public static String[] safeCommand(String cmdLine) {
        if (cmdLine == null) {
            return null;
        }
        String[] argv = cmdLine.trim().split("\\s+");
        if (argv.length == 0 || !ALLOWED_COMMANDS.contains(argv[0])) {
            return null;
        }
        for (int i = 1; i < argv.length; i++) {
            if (cmdFilter(argv[i]) == null) {
                return null;
            }
        }
        return argv;
    }


    /**
     * 过滤mybatis中order by不能用#的情况。
     * 严格限制用户输入只能包含<code>a-zA-Z0-9_-.</code>字符。
     *
     * @param sql sql
     * @return 安全sql，否则返回null
     */
    public static String sqlFilter(String sql) {
        if (!FILTER_PATTERN.matcher(sql).matches()) {
            return null;
        }
        return sql;
    }

    /**
     * 将非<code>0-9a-zA-Z/-.</code>的字符替换为空
     *
     * @param str 字符串
     * @return 被过滤的字符串
     */
    public static String replaceSpecialStr(String str) {
        StringBuilder sb = new StringBuilder();
        str = str.toLowerCase();
        for(int i = 0; i < str.length(); i++) {
            char ch = str.charAt(i);
            // 如果是0-9
            if (ch >= 48 && ch <= 57 ){
                sb.append(ch);
            }
            // 如果是a-z
            else if(ch >= 97 && ch <= 122) {
                sb.append(ch);
            }
            else if(ch == '/' || ch == '.' || ch == '-'){
                sb.append(ch);
            }
        }

        return sb.toString();
    }

    public static void main(String[] args) {
    }

}