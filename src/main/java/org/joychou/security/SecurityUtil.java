package org.joychou.security;

import org.joychou.config.WebConfig;
import org.joychou.security.ssrf.SSRFChecker;
import org.joychou.security.ssrf.SocketHook;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.URLDecoder;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


public class SecurityUtil {

    private static final Pattern FILTER_PATTERN = Pattern.compile("^[a-zA-Z0-9_/\\.-]+$");
    private static Logger logger = LoggerFactory.getLogger(SecurityUtil.class);


    /**
     * Determine if the URL starts with HTTP.
     *
     * @param url url
     * @return true or false
     */
    public static boolean isHttp(String url) {
        return url.startsWith("http://") || url.startsWith("https://");
    }


    private static final String HOST_ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789.-";
    private static final String HOST_LABEL = "[A-Z0-9]+(?:-+[A-Z0-9]+)*";
    private static final String PATH_CHARS = "[A-Za-z0-9._~:@!$&'()*+,;=%/-]";
    private static final String QUERY_CHARS = "[A-Za-z0-9._~:@!$&'()*+,;=%/?-]";

    /**
     * Get http url host. The url is parsed with the strict grammar of
     * {@link #parseHttpTarget(String)} (pure string parsing, no network access); the returned
     * host is rebuilt from a fixed alphabet and is lower case.
     *
     * @param url url
     * @return host, or an empty string when the url is not a well formed http(s) url
     */
    public static String gethost(String url) {
        if (url == null || url.length() > MAX_REDIRECT_URL_LENGTH) {
            return "";
        }
        Matcher m = HTTP_AUTHORITY_PATTERN.matcher(url);
        if (!m.matches()) {
            return "";
        }
        String rawHost = m.group(1);
        if (rawHost.startsWith("[")) {
            String ip = normalizeIpLiteral(rawHost.substring(1, rawHost.length() - 1));
            return ip == null ? "" : "[" + ip + "]";
        }
        return rawHost.length() > 253 ? "" : rebuildFromAlphabet(rawHost.toLowerCase(), HOST_ALPHABET);
    }

    /**
     * Only the scheme and authority of a url are validated (host and optional port, no user info,
     * no backslash); whatever follows the authority is not interpreted. Group 1 is the host.
     */
    private static final Pattern HTTP_AUTHORITY_PATTERN = Pattern.compile(
            "https?://(\\[[0-9A-F:.]{2,45}\\]|" + HOST_LABEL + "(?:\\." + HOST_LABEL + ")*\\.?)"
                    + "(?::[0-9]{1,5})?(?:[/?#][^\\s\\\\\\p{Cntrl}]*)?",
            Pattern.CASE_INSENSITIVE);


    /** A bare host name (no scheme, port or path). */
    private static final Pattern BARE_HOST_PATTERN = Pattern.compile(HOST_LABEL + "(?:\\." + HOST_LABEL + ")*",
            Pattern.CASE_INSENSITIVE);

    /**
     * Validate a bare host name or an IPv4 / IPv6 literal (no scheme, port, path or user info) and
     * rebuild it from a fixed alphabet. This is pure string handling, there is no name resolution.
     *
     * @param host candidate host, may be null
     * @return the lower case host (IPv6 literals canonical and without brackets), or null if malformed
     */
    public static String parseBareHost(String host) {
        if (host == null || host.isEmpty() || host.length() > 253) {
            return null;
        }
        if (host.indexOf(':') >= 0) {
            return normalizeIpLiteral(host);
        }
        if (!BARE_HOST_PATTERN.matcher(host).matches()) {
            return null;
        }
        return rebuildFromAlphabet(host.toLowerCase(), HOST_ALPHABET);
    }


    /**
     * A syntactically validated http(s) url. Every component is rebuilt from a fixed
     * alphabet (see {@link #parseHttpTarget(String)}), never copied from the request string.
     */
    public static final class HttpTarget {
        private final String scheme;
        private final String host;
        private final int port;
        private final String rest;
        private final String pathAndQuery;

        private HttpTarget(String scheme, String host, int port, String path, String query, String fragment) {
            this.scheme = scheme;
            this.host = host;
            this.port = port;
            this.rest = buildRest(path, query, fragment);
            this.pathAndQuery = buildRest(path.isEmpty() ? "/" : path, query, null);
        }

        /** @return the literal "http" or "https" */
        public String getScheme() {
            return scheme;
        }

        /** @return lower case host name, or a bracketed canonical IPv6 literal */
        public String getHost() {
            return host;
        }

        /** @return the port, or -1 for the default port of the scheme */
        public int getPort() {
            return port;
        }

        /** @return raw path (never empty, "/" at least) followed by the raw query, no fragment */
        public String getPathAndQuery() {
            return pathAndQuery;
        }

        /** @return the url rebuilt from the validated components */
        public String toUriString() {
            StringBuilder sb = new StringBuilder(scheme).append("://").append(host);
            if (port != -1) {
                sb.append(':').append(port);
            }
            return sb.append(rest).toString();
        }
    }

    /**
     * scheme://host[:port][/path][?query][#fragment] with a closed character set: no user info,
     * no backslash, no whitespace, no control or non ASCII characters.
     * Groups: 1 scheme, 2 host, 3 port, 4 path, 5 query, 6 fragment.
     */
    private static final Pattern HTTP_URL_PATTERN = Pattern.compile(
            "(https?)://(\\[[0-9A-F:.]{2,45}\\]|" + HOST_LABEL + "(?:\\." + HOST_LABEL + ")*\\.?)"
                    + "(?::([0-9]{1,5}))?(/" + PATH_CHARS + "*)?(?:\\?(" + QUERY_CHARS + "*))?(?:#(" + QUERY_CHARS + "*))?",
            Pattern.CASE_INSENSITIVE);

    /** Same-origin reference. Groups: 1 path, 2 query, 3 fragment. */
    private static final Pattern RELATIVE_URL_PATTERN = Pattern.compile(
            "(/" + PATH_CHARS + "*)(?:\\?(" + QUERY_CHARS + "*))?(?:#(" + QUERY_CHARS + "*))?");

    /** A '%' that is not followed by two hex digits. */
    private static final Pattern BAD_PERCENT_PATTERN = Pattern.compile("%(?![0-9A-Fa-f]{2})");

    /**
     * Strictly parse an absolute http/https url by pure string handling (no java.net.URL / URI
     * construction, no DNS, no network access). The result is rebuilt from the match: the scheme is
     * a fixed literal, the host is rebuilt from {@link #HOST_ALPHABET}, the port is an int and path,
     * query and fragment are rebuilt from the url alphabet.
     *
     * @param url url from any source, may be null
     * @return the parsed target, or null when the url is not a well formed http(s) url
     */
    public static HttpTarget parseHttpTarget(String url) {
        if (url == null || url.isEmpty() || url.length() > MAX_REDIRECT_URL_LENGTH
                || BAD_PERCENT_PATTERN.matcher(url).find()) {
            return null;
        }
        Matcher m = HTTP_URL_PATTERN.matcher(url);
        if (!m.matches()) {
            return null;
        }
        String scheme = "https".equalsIgnoreCase(m.group(1)) ? "https" : "http";
        String rawHost = m.group(2);
        String host;
        if (rawHost.startsWith("[")) {
            String ip = normalizeIpLiteral(rawHost.substring(1, rawHost.length() - 1));
            if (ip == null) {
                return null;
            }
            host = "[" + ip + "]";
        } else {
            if (rawHost.length() > 253) {
                return null;
            }
            host = rebuildFromAlphabet(rawHost.toLowerCase(), HOST_ALPHABET);
        }
        int port = -1;
        if (m.group(3) != null) {
            port = Integer.parseInt(m.group(3));
            if (port < 1 || port > 65535) {
                return null;
            }
        }
        return new HttpTarget(scheme, host, port,
                m.group(4) == null ? "" : m.group(4), m.group(5), m.group(6));
    }

    /** Rebuild "path[?query][#fragment]" from the url alphabet. */
    private static String buildRest(String path, String query, String fragment) {
        StringBuilder sb = new StringBuilder(rebuildFromAlphabet(path, URL_ALPHABET));
        if (query != null) {
            sb.append('?').append(rebuildFromAlphabet(query, URL_ALPHABET));
        }
        if (fragment != null) {
            sb.append('#').append(rebuildFromAlphabet(fragment, URL_ALPHABET));
        }
        return sb.toString();
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
        return isSafeHttpUrl(url);
    }

    /** Ports a server side request may target (-1 means the default port of the scheme). */
    private static final java.util.Set<Integer> ALLOWED_PORTS = new java.util.HashSet<Integer>(
            java.util.Arrays.asList(-1, 80, 443, 8080, 8443));

    /**
     * Strict check for a user supplied URL that the server is about to request.
     * The URL must be an absolute http/https URI without user info, use an allowlisted port,
     * and every address the host resolves to must be a public one
     * (see {@link #resolvePublicAddress(String)}).
     * Callers must also disable redirect following, otherwise a redirect could lead
     * to a target that was never validated.
     *
     * @param url The url that needs to check.
     * @return Safe url returns true. Dangerous or malformed url returns false.
     */
    public static boolean isSafeHttpUrl(String url) {
        return checkHttpTarget(url) != null;
    }


    /**
     * Same checks as {@link #isSafeHttpUrl(String)}, but returns the parsed target. The caller
     * must request {@link HttpTarget#toUriString()} (or its components), which is rebuilt from the
     * validated pieces and never the original request string.
     *
     * @param url The url that needs to check.
     * @return the validated target, or null when the url is dangerous or malformed
     */
    public static HttpTarget checkHttpTarget(String url) {
        HttpTarget target = parseHttpTarget(url);
        if (target == null || !ALLOWED_PORTS.contains(target.getPort())) {
            return null;
        }
        return resolvePublicAddress(target.getHost()) != null ? target : null;
    }


    /**
     * Resolve the host and make sure that none of its addresses is a loopback, link-local
     * (cloud metadata), private, multicast, unspecified or otherwise internal address.
     * Fails closed: any resolution or configuration error returns false.
     *
     * @param host host name or ip literal
     * @return true only if every resolved address is public
     */
    public static boolean isPublicHost(String host) {
        return resolvePublicAddress(host) != null;
    }


    /**
     * Resolve the host exactly once and validate <b>every</b> returned address.
     * The returned address is the one a caller can connect to (or write into the connection
     * string) so that the validated address is the address that is used (no second DNS lookup,
     * which prevents DNS rebinding). Fails closed: any resolution error returns null.
     * Non canonical dotted numeric hosts (octal / short forms such as 012.1 or 0177.0.0.1)
     * are rejected because different parsers disagree on their value.
     *
     * @param host host name or ip literal
     * @return the first resolved address when all resolved addresses are public, otherwise null
     */
    public static InetAddress resolvePublicAddress(String host) {
        InetAddress[] addresses = resolvePublicAddresses(host);
        return addresses == null ? null : addresses[0];
    }


    /**
     * Same as {@link #resolvePublicAddress(String)} but returns all validated addresses, so that
     * a DNS resolver plugged into an HTTP client can hand exactly these addresses to the socket.
     *
     * @param host host name or ip literal
     * @return all resolved addresses when every one is public, otherwise null
     */
    public static InetAddress[] resolvePublicAddresses(String host) {
        if (host == null || host.isEmpty() || !isCanonicalHost(host)) {
            return null;
        }
        try {
            InetAddress[] addresses = InetAddress.getAllByName(host);
            if (addresses.length == 0) {
                return null;
            }
            for (InetAddress address : addresses) {
                if (!isPublicAddress(address)) {
                    return null;
                }
            }
            return addresses;
        } catch (Exception e) {
            logger.error("Host resolution failed: " + e.getClass().getSimpleName());
            return null;
        }
    }


    /**
     * A host made only of digits and dots must be a canonical dotted quad (four decimal
     * parts, 0-255, no leading zeros).
     */
    private static boolean isCanonicalHost(String host) {
        boolean numeric = true;
        for (int i = 0; i < host.length(); i++) {
            char ch = host.charAt(i);
            if ((ch < '0' || ch > '9') && ch != '.') {
                numeric = false;
                break;
            }
        }
        if (!numeric) {
            return true;
        }
        String[] parts = host.split("\\.", -1);
        if (parts.length != 4) {
            return false;
        }
        for (String part : parts) {
            if (part.isEmpty() || part.length() > 3 || (part.length() > 1 && part.charAt(0) == '0')
                    || Integer.parseInt(part) > 255) {
                return false;
            }
        }
        return true;
    }


    private static boolean isPublicAddress(InetAddress address) {
        if (address.isAnyLocalAddress() || address.isLoopbackAddress()
                || address.isLinkLocalAddress() || address.isSiteLocalAddress()
                || address.isMulticastAddress()) {
            return false;
        }
        byte[] raw = address.getAddress();
        if (address instanceof Inet4Address) {
            int first = raw[0] & 0xFF;
            int second = raw[1] & 0xFF;
            int third = raw[2] & 0xFF;
            // 0.0.0.0/8, carrier-grade NAT 100.64.0.0/10, IETF protocol 192.0.0.0/24,
            // benchmarking 198.18.0.0/15, reserved 240.0.0.0/4 (incl. broadcast)
            if (first == 0 || first >= 240
                    || (first == 100 && second >= 64 && second <= 127)
                    || (first == 192 && second == 0 && third == 0)
                    || (first == 198 && (second == 18 || second == 19))) {
                return false;
            }
            return !SSRFChecker.isInternalIp(address.getHostAddress());
        }
        // IPv6 unique local address fc00::/7
        if ((raw[0] & 0xFE) == 0xFC) {
            return false;
        }
        // IPv4-compatible ::a.b.c.d
        boolean zeroPrefix = true;
        for (int i = 0; i < 12; i++) {
            if (raw[i] != 0) {
                zeroPrefix = false;
                break;
            }
        }
        if (zeroPrefix) {
            return false;
        }
        // 6to4 2002::/16 and NAT64 64:ff9b::/96 embed an IPv4 address
        if ((raw[0] == 0x20 && raw[1] == 0x02)
                || (raw[0] == 0x00 && raw[1] == 0x64 && (raw[2] & 0xFF) == 0xFF && (raw[3] & 0xFF) == 0x9B)) {
            return false;
        }
        return true;
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
        if (filepath == null || filepath.isEmpty()) {
            return null;
        }
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

        if (temp.isEmpty() || temp.contains("..") || temp.charAt(0) == '/') {
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
     * Fixed server-side command table: normalized command line -> fixed argv.
     * For {@link #parseAllowedCommand(String)} user data can only select a row.
     */
    private static final java.util.Map<String, String[]> COMMAND_TABLE;

    static {
        java.util.Map<String, String[]> table = new java.util.HashMap<String, String[]>();
        table.put("whoami", new String[]{"whoami"});
        table.put("id", new String[]{"id"});
        table.put("date", new String[]{"date"});
        table.put("uname", new String[]{"uname"});
        table.put("uname -a", new String[]{"uname", "-a"});
        table.put("hostname", new String[]{"hostname"});
        table.put("pwd", new String[]{"pwd"});
        table.put("ls", new String[]{"ls"});
        table.put("ls -l", new String[]{"ls", "-l"});
        table.put("ls -a", new String[]{"ls", "-a"});
        table.put("ls -la", new String[]{"ls", "-la"});
        COMMAND_TABLE = java.util.Collections.unmodifiableMap(table);
    }

    /**
     * Select a command from the fixed server-side table. The user string only selects a row;
     * the returned argv consists exclusively of the table's own fixed elements (no user data).
     *
     * @param cmd command line, whitespace separated
     * @return argv list that can be passed to ProcessBuilder, or null if not allowed
     */
    public static java.util.List<String> parseAllowedCommand(String cmd) {
        if (cmd == null || cmd.trim().isEmpty()) {
            return null;
        }
        String normalized = cmd.trim().replaceAll("\\s+", " ");
        for (java.util.Map.Entry<String, String[]> entry : COMMAND_TABLE.entrySet()) {
            if (entry.getKey().equals(normalized)) {
                return new ArrayList<String>(java.util.Arrays.asList(entry.getValue()));
            }
        }
        return null;
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

    /**
     * Remove CR, LF and other ISO control characters so that a value can be safely
     * placed in an HTTP response header (prevents CRLF / header injection).
     *
     * @param value header value, may be null
     * @return the value without control characters, or null if value is null
     */
    public static String cleanHeaderValue(String value) {
        if (value == null) {
            return null;
        }
        // Reject (safe default: empty value) anything with control characters or non-ASCII.
        for (int i = 0; i < value.length(); i++) {
            char ch = value.charAt(i);
            if (ch < 0x20 || ch > 0x7E) {
                return "";
            }
        }
        return rebuildFromAlphabet(value, HEADER_VALUE_ALPHABET);
    }

    private static final String ALNUM_ALPHABET =
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    /** Characters allowed in a generic header value. */
    private static final String HEADER_VALUE_ALPHABET = ALNUM_ALPHABET + "._~:/?#@!$&'()*+,;=%- ";
    /** Characters allowed in a redirect url (RFC 3986 reserved + unreserved + percent). */
    private static final String URL_ALPHABET = ALNUM_ALPHABET + "._~:/?#@!$&'()*+,;=%-";
    /** Characters allowed in a download file name. */
    private static final String FILE_NAME_ALPHABET = ALNUM_ALPHABET + "._-";

    /**
     * Build a new string whose every character is taken from the fixed alphabet constant
     * (characters of the input that are not in the alphabet are dropped). The result never
     * contains a character that is not literally part of the alphabet.
     */
    private static String rebuildFromAlphabet(String value, String alphabet) {
        StringBuilder sb = new StringBuilder(value.length());
        for (int i = 0; i < value.length(); i++) {
            int idx = alphabet.indexOf(value.charAt(i));
            if (idx >= 0) {
                sb.append(alphabet.charAt(idx));
            }
        }
        return sb.toString();
    }

    /** Characters a JSONP callback name is built from: JavaScript identifier characters and '.'. */
    private static final String JSONP_CALLBACK_ALPHABET = ALNUM_ALPHABET + "_$.";
    private static final int MAX_JSONP_CALLBACK_LENGTH = 64;

    /** Constant callback name used when the requested one is missing, malformed or not allowed. */
    public static final String DEFAULT_JSONP_CALLBACK = "callback";

    /**
     * Resolve the callback name of a JSONP response. The result is never the request string:
     * it is rebuilt character by character, every output character being taken from the
     * constant {@link #JSONP_CALLBACK_ALPHABET}. A request value with any character outside the
     * alphabet, longer than 64 characters, not starting with a letter, '_' or '$', or with a
     * leading / trailing / doubled '.' yields {@link #DEFAULT_JSONP_CALLBACK}.
     * When the property {@code joychou.security.jsonp.allowed.callbacks} is not empty the
     * rebuilt name must additionally equal one of its entries.
     *
     * @param requested the callback request parameter, may be null
     * @return a callback name that is safe to place in JavaScript code, never null
     */
    public static String getSafeJsonpCallback(String requested) {
        if (requested == null || requested.isEmpty() || requested.length() > MAX_JSONP_CALLBACK_LENGTH) {
            return DEFAULT_JSONP_CALLBACK;
        }
        StringBuilder sb = new StringBuilder(requested.length());
        for (int i = 0; i < requested.length(); i++) {
            int idx = JSONP_CALLBACK_ALPHABET.indexOf(requested.charAt(i));
            if (idx < 0) {
                return DEFAULT_JSONP_CALLBACK;
            }
            sb.append(JSONP_CALLBACK_ALPHABET.charAt(idx));
        }
        String name = sb.toString();
        char first = name.charAt(0);
        boolean validFirst = (first >= 'a' && first <= 'z') || (first >= 'A' && first <= 'Z')
                || first == '_' || first == '$';
        if (!validFirst || name.charAt(0) == '.' || name.charAt(name.length() - 1) == '.'
                || name.contains("..")) {
            return DEFAULT_JSONP_CALLBACK;
        }
        String[] allowed = WebConfig.getJsonpAllowedCallbacks();
        if (allowed != null) {
            boolean restricted = false;
            for (String entry : allowed) {
                if (entry != null && !entry.trim().isEmpty()) {
                    restricted = true;
                    if (entry.trim().equals(name)) {
                        return name;
                    }
                }
            }
            if (restricted) {
                return DEFAULT_JSONP_CALLBACK;
            }
        }
        return name;
    }

    /** Characters that may appear verbatim in a log message (no whitespace, no control chars). */
    private static final String LOG_VALUE_ALPHABET = ALNUM_ALPHABET + "._~:/@+,;=%-";
    private static final int MAX_LOG_VALUE_LENGTH = 200;

    /**
     * Build a value that is safe to write to a log (prevents CRLF / log forging). The result is
     * a new string: null becomes "null", the value is truncated to 200 characters, and every
     * character outside [A-Za-z0-9._~:/@+,;=%-] (including space, CR, LF, tab, other control
     * and unicode line separator characters) is replaced by '_'.
     *
     * @param value request derived value, may be null
     * @return a log-safe string
     */
    public static String sanitizeForLog(String value) {
        if (value == null) {
            return "null";
        }
        int len = Math.min(value.length(), MAX_LOG_VALUE_LENGTH);
        StringBuilder sb = new StringBuilder(len);
        for (int i = 0; i < len; i++) {
            int idx = LOG_VALUE_ALPHABET.indexOf(value.charAt(i));
            sb.append(idx >= 0 ? LOG_VALUE_ALPHABET.charAt(idx) : '_');
        }
        return sb.toString();
    }

    /**
     * Build a safe download file name for a Content-Disposition header. The name is rebuilt
     * from the characters [A-Za-z0-9._-] only; an empty result falls back to "download".
     *
     * @param name file name derived from user input, may be null
     * @return a file name that is safe to place in a response header
     */
    public static String getSafeAttachmentFileName(String name) {
        if (name == null) {
            return "download";
        }
        String safe = rebuildFromAlphabet(name, FILE_NAME_ALPHABET);
        return safe.isEmpty() ? "download" : safe;
    }

    /**
     * Server-side CORS origin allowlist (full origins, scheme://host[:port]). It is built from
     * configuration only: the property {@code joychou.security.cors.allowed.origins} plus the
     * exact http/https origins of the hosts in url/url_safe_domain.xml (hosts that are also
     * block-listed are dropped). The default is an empty list.
     */
    private static List<String> corsAllowedOrigins() {
        List<String> allowed = new ArrayList<String>();
        String[] configured = WebConfig.getCorsAllowedOrigins();
        if (configured != null) {
            for (String entry : configured) {
                if (entry != null && !entry.trim().isEmpty()) {
                    allowed.add(entry.trim());
                }
            }
        }
        for (String safeDomain : WebConfig.getSafeDomains()) {
            if (safeDomain != null && !safeDomain.trim().isEmpty()) {
                allowed.add("https://" + safeDomain.trim());
                allowed.add("http://" + safeDomain.trim());
            }
        }
        return allowed;
    }

    /**
     * Match a CORS request Origin against the fixed server-side allowlist
     * ({@link #corsAllowedOrigins()}) by exact equality. Allowlist entries must pass the
     * safe/block domain check ({@link #checkURL(String)}).
     *
     * The returned value is the allowlist ELEMENT, never the request string: a caller that
     * writes it to Access-Control-Allow-Origin never reflects request data. Null, "null",
     * wildcard and unknown origins return null (the caller must send no CORS headers).
     *
     * @param requestOrigin the Origin request header, may be null
     * @return the matching allowlist entry, otherwise null
     */
    public static String matchAllowedOrigin(String requestOrigin) {
        if (requestOrigin == null || requestOrigin.isEmpty()) {
            return null;
        }
        for (String allowed : corsAllowedOrigins()) {
            if (allowed.equals(requestOrigin) && !"*".equals(allowed) && checkURL(allowed) != null) {
                return allowed;
            }
        }
        return null;
    }

    /**
     * Validate a user supplied redirect target.
     * Allowed: a same-origin absolute path (single leading slash), or an http(s) url whose host
     * passes {@link #checkURL(String)} (safe/block domain config). Control characters, whitespace,
     * backslashes, protocol-relative urls ("//host") and userinfo ("user@host") are rejected.
     *
     * The returned value is never the request string itself: it is rebuilt from the parsed
     * components (fixed scheme literal, validated host, port, raw path/query/fragment), so a
     * caller that redirects to the return value never redirects to unparsed request data.
     *
     * @param url the redirect target from the request, may be null
     * @return a freshly built url that is safe to redirect to, otherwise null
     */
    public static String getSafeRedirectUrl(String url) {
        if (url == null || url.isEmpty() || url.length() > MAX_REDIRECT_URL_LENGTH) {
            return null;
        }
        for (int i = 0; i < url.length(); i++) {
            char ch = url.charAt(i);
            if (ch == '\\' || Character.isISOControl(ch) || Character.isWhitespace(ch)) {
                return null;
            }
        }
        if (hasEncodedControlOrBackslash(url)) {
            return null;
        }

        if (url.startsWith("/")) {
            // Same-origin path only: no "//host", no scheme, no authority.
            Matcher rel = RELATIVE_URL_PATTERN.matcher(url);
            if (url.startsWith("//") || BAD_PERCENT_PATTERN.matcher(url).find() || !rel.matches()) {
                return null;
            }
            String path = rel.group(1);
            if (decodeFully(path).startsWith("//")) {
                return null;
            }
            return buildRest(path, rel.group(2), rel.group(3));
        }

        HttpTarget target = parseHttpTarget(url);
        if (target == null) {
            return null;
        }
        String host = target.getHost();
        if (!SAFE_HOST_PATTERN.matcher(host).matches()) {
            return null;
        }
        // Allow/block domain config (exact host or proper dot-boundary suffix).
        if (checkURL(target.getScheme() + "://" + host) == null) {
            return null;
        }
        return target.toUriString();
    }

    /**
     * Same as {@link #getSafeRedirectUrl(String)} but never returns null: an invalid
     * target falls back to the application root.
     *
     * @param url the redirect target from the request, may be null
     * @return a safe redirect target, "/" when the url is not allowed
     */
    public static String getSafeRedirectUrlOrDefault(String url) {
        String safe = getSafeRedirectUrl(url);
        if (safe == null) {
            return "/";
        }
        // Final rebuild from the fixed url alphabet; anything outside it falls back to "/".
        String rebuilt = rebuildFromAlphabet(safe, URL_ALPHABET);
        return rebuilt.equals(safe) ? rebuilt : "/";
    }

    private static final int MAX_REDIRECT_URL_LENGTH = 2048;
    private static final Pattern SAFE_HOST_PATTERN = Pattern.compile("^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$");

    /**
     * Percent-decode repeatedly (handles double encoding such as %255c). '+' is kept as is.
     * Returns the input unchanged text when it cannot be decoded.
     */
    private static String decodeFully(String value) {
        String current = value;
        for (int i = 0; i < 5; i++) {
            if (current.indexOf('%') == -1) {
                return current;
            }
            try {
                String next = URLDecoder.decode(current.replace("+", "%2B"), "UTF-8");
                if (next.equals(current)) {
                    return current;
                }
                current = next;
            } catch (UnsupportedEncodingException e) {
                return current;
            } catch (IllegalArgumentException e) {
                return current;
            }
        }
        return current;
    }

    private static boolean hasEncodedControlOrBackslash(String value) {
        String decoded = decodeFully(value);
        if (decoded.indexOf('%') != -1 && !decoded.equals(value)) {
            // still encoded after the maximum number of rounds: too deeply nested
            String again = decodeFully(decoded);
            if (!again.equals(decoded)) {
                return true;
            }
        }
        for (int i = 0; i < decoded.length(); i++) {
            char ch = decoded.charAt(i);
            if (ch == '\\' || Character.isISOControl(ch)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Parse a literal IPv4 (dotted quad) or IPv6 (hex groups, optional "::") address without
     * any name resolution and return its canonical text, rebuilt from the address bytes.
     *
     * @param text candidate text, may be null
     * @return canonical address text, or null if text is not a literal ip address
     */
    public static String normalizeIpLiteral(String text) {
        if (text == null || text.isEmpty() || text.length() > 45) {
            return null;
        }
        byte[] raw = text.indexOf(':') >= 0 ? parseIpv6Literal(text) : parseIpv4Literal(text);
        if (raw == null) {
            return null;
        }
        try {
            return InetAddress.getByAddress(raw).getHostAddress();
        } catch (java.net.UnknownHostException e) {
            return null;
        }
    }

    private static byte[] parseIpv4Literal(String text) {
        String[] parts = text.split("\\.", -1);
        if (parts.length != 4) {
            return null;
        }
        byte[] raw = new byte[4];
        for (int i = 0; i < 4; i++) {
            String part = parts[i];
            if (part.isEmpty() || part.length() > 3 || (part.length() > 1 && part.charAt(0) == '0')) {
                return null;
            }
            int value = 0;
            for (int j = 0; j < part.length(); j++) {
                char ch = part.charAt(j);
                if (ch < '0' || ch > '9') {
                    return null;
                }
                value = value * 10 + (ch - '0');
            }
            if (value > 255) {
                return null;
            }
            raw[i] = (byte) value;
        }
        return raw;
    }

    private static byte[] parseIpv6Literal(String text) {
        for (int i = 0; i < text.length(); i++) {
            char ch = text.charAt(i);
            boolean hex = (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F');
            if (!hex && ch != ':') {
                return null;
            }
        }
        if (text.contains(":::")) {
            return null;
        }
        int gap = text.indexOf("::");
        if (gap != text.lastIndexOf("::")) {
            return null;
        }
        int[] head;
        int[] tail;
        if (gap < 0) {
            head = parseHexGroups(text);
            tail = new int[0];
            if (head == null || head.length != 8) {
                return null;
            }
        } else {
            head = parseHexGroups(text.substring(0, gap));
            tail = parseHexGroups(text.substring(gap + 2));
            if (head == null || tail == null || head.length + tail.length > 7) {
                return null;
            }
        }
        byte[] raw = new byte[16];
        for (int i = 0; i < head.length; i++) {
            raw[2 * i] = (byte) (head[i] >> 8);
            raw[2 * i + 1] = (byte) head[i];
        }
        for (int i = 0; i < tail.length; i++) {
            int pos = 8 - tail.length + i;
            raw[2 * pos] = (byte) (tail[i] >> 8);
            raw[2 * pos + 1] = (byte) tail[i];
        }
        return raw;
    }

    /** Parse colon separated groups of 1-4 hex digits; an empty string is zero groups. */
    private static int[] parseHexGroups(String text) {
        if (text.isEmpty()) {
            return new int[0];
        }
        String[] groups = text.split(":", -1);
        int[] values = new int[groups.length];
        for (int i = 0; i < groups.length; i++) {
            String group = groups[i];
            if (group.isEmpty() || group.length() > 4) {
                return null;
            }
            int value = 0;
            for (int j = 0; j < group.length(); j++) {
                int digit = Character.digit(group.charAt(j), 16);
                if (digit < 0) {
                    return null;
                }
                value = value * 16 + digit;
            }
            values[i] = value;
        }
        return values;
    }

    public static void main(String[] args) {
    }

}