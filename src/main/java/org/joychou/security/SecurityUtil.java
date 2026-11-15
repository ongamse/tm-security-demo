package org.joychou.security;

import org.joychou.config.WebConfig;
import org.joychou.security.ssrf.PinnedSslSocketFactory;
import org.joychou.security.ssrf.SSRFChecker;
import org.joychou.security.ssrf.SocketHook;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.HttpsURLConnection;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLDecoder;
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
        try {
            URI uri = new URI(url);
            String host = uri.getHost();
            return host == null ? "" : host.toLowerCase();
        } catch (URISyntaxException e) {
            return "";
        }
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

        if (url.startsWith("/")) {
            // Same-site path only: reject "//host" and its decoded variants.
            if (url.startsWith("//") || decoded.startsWith("//")) {
                return null;
            }
            return url;
        }

        return checkURL(url);
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

        private SafeTarget(String scheme, String host, int port, String file, InetAddress[] addresses) {
            this.scheme = scheme;
            this.host = host;
            this.port = port;
            this.file = file;
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
            boolean defaultPort = port == -1 || (port == 80 && !isHttps()) || (port == 443 && isHttps());
            return defaultPort ? host : host + ":" + port;
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
         * (send {@link #getHostHeader()} as Host header). https targets keep the validated host name so
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
        if (h.startsWith("[")) {
            return IPV6_LITERAL.matcher(h).matches() ? h : null;
        }
        if (NUMERIC_HOST.matcher(h).matches()) {
            return STRICT_IPV4.matcher(h).matches() ? h : null;
        }
        return HOST_PATTERN.matcher(h).matches() ? h : null;
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
     * The single SSRF gate for outbound requests. Parses the user url to a {@link URI}, requires
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
            URI uri = new URI(url);
            String scheme = uri.getScheme() == null ? "" : uri.getScheme().toLowerCase(Locale.ROOT);
            boolean https = "https".equals(scheme);
            if (!https && !("http".equals(scheme) && isHttpAllowed())) {
                throw new IOException("[-] SSRF check failed. Illegal scheme.");
            }
            if (uri.getRawUserInfo() != null) {
                throw new IOException("[-] SSRF check failed. Userinfo not allowed.");
            }
            String host = canonicalHost(uri.getHost());
            if (host == null) {
                throw new IOException("[-] SSRF check failed. Illegal host.");
            }
            int port = uri.getPort();
            if (port != -1 && (port < 1 || port > 65535)) {
                throw new IOException("[-] SSRF check failed. Illegal port.");
            }

            InetAddress[] addrs = InetAddress.getAllByName(host);
            for (InetAddress addr : addrs) {
                if (!isPublicAddress(addr)) {
                    throw new IOException("[-] SSRF check failed. Internal address.");
                }
            }

            String path = uri.getRawPath();
            String file = (path == null || path.isEmpty()) ? "/" : path;
            if (uri.getRawQuery() != null) {
                file = file + "?" + uri.getRawQuery();
            }
            return new SafeTarget(scheme, host, port, file, addrs);
        } catch (URISyntaxException | UnknownHostException e) {
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
     *   <li>http: the url is re-built with the pinned literal IP. The JDK drops a restricted Host header,
     *       so name based virtual hosting is not available over plain http; set
     *       <code>SSRF_ALLOW_HTTP=false</code> to allow https only.</li>
     * </ul>
     */
    public static HttpURLConnection openConnection(SafeTarget target) throws IOException {
        HttpURLConnection conn = (HttpURLConnection) (target.isHttps() ? target.getCanonicalUrl() : target.getUrl())
                .openConnection();
        conn.setInstanceFollowRedirects(false);
        if (conn instanceof HttpsURLConnection) {
            ((HttpsURLConnection) conn).setSSLSocketFactory(new PinnedSslSocketFactory());
        } else {
            conn.setRequestProperty("Host", target.getHostHeader());
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