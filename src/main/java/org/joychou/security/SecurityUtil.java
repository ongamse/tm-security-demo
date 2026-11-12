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
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLDecoder;
import java.util.ArrayList;
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


    /**
     * Get http url host.
     *
     * @param url url
     * @return host
     */
    public static String gethost(String url) {
        try {
            URI uri = new URI(url);
            return uri.getHost().toLowerCase();
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
        if (url == null) {
            return false;
        }
        try {
            URI uri = new URI(url);
            String scheme = uri.getScheme();
            if (scheme == null || !("http".equalsIgnoreCase(scheme) || "https".equalsIgnoreCase(scheme))) {
                return false;
            }
            if (uri.getRawUserInfo() != null || !ALLOWED_PORTS.contains(uri.getPort())) {
                return false;
            }
            return resolvePublicAddress(uri.getHost()) != null;
        } catch (URISyntaxException e) {
            return false;
        }
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

    /** A path token: no leading '-', no whitespace/quotes/shell metacharacters. */
    private static final Pattern PATH_TOKEN_PATTERN = Pattern.compile("^[A-Za-z0-9._/][A-Za-z0-9._/-]{0,127}$");

    /** Host (optionally with port) for the curl helper: no leading '-', no scheme, no userinfo. */
    private static final Pattern CURL_HOST_PATTERN =
            Pattern.compile("^[A-Za-z0-9][A-Za-z0-9.-]{0,252}(:[0-9]{1,5})?$");

    private static boolean isSafePathToken(String token) {
        return token != null && PATH_TOKEN_PATTERN.matcher(token).matches() && !token.contains("..");
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
     * Build the argv for a directory listing of a user supplied path:
     * fixed {@code ls -la --} followed by one validated path token.
     *
     * @param path user supplied path
     * @return argv for ProcessBuilder, or null if the path is not a plain path token
     */
    public static java.util.List<String> buildListCommand(String path) {
        if (!isSafePathToken(path)) {
            return null;
        }
        java.util.List<String> argv = new ArrayList<String>(java.util.Arrays.asList(COMMAND_TABLE.get("ls -la")));
        argv.add("--");
        argv.add(path);
        return argv;
    }

    /**
     * Build the argv for fetching a host with curl: fixed options, http(s) only, and one
     * validated host[:port] token after {@code --}.
     *
     * @param host host[:port] (e.g. from the Host header)
     * @return argv for ProcessBuilder, or null if the host is not a plain host token
     */
    public static java.util.List<String> buildCurlHostCommand(String host) {
        if (host == null || !CURL_HOST_PATTERN.matcher(host).matches() || host.contains("..")) {
            return null;
        }
        return new ArrayList<String>(java.util.Arrays.asList(
                "curl", "--proto", "=http,https", "--max-time", "10", "--", host));
    }

    /** SpEL keywords that may appear as operators/literals. */
    private static final Pattern SPEL_KEYWORDS =
            Pattern.compile("\\b(true|false|null|and|or|not|lt|gt|le|ge|eq|ne|div|mod)\\b");
    private static final Pattern SPEL_STRING_LITERAL = Pattern.compile("'[^'\\\\\"]*'");
    private static final Pattern SPEL_REMAINDER = Pattern.compile("^[0-9\\s+\\-*/%^()<>=!&|?:,{}\\[\\].]*$");
    private static final Pattern SPEL_BAD_DOT = Pattern.compile("(?<![0-9])\\.|\\.(?![0-9])");

    /**
     * Grammar allowlist for a user supplied SpEL expression: only literals (numbers, quoted
     * strings without escapes, true/false/null), arithmetic/comparison/logical operators,
     * parentheses and inline list/map literals. Type references, constructors, variables,
     * bean references and method/property navigation are rejected.
     *
     * @param expression the expression text
     * @return true if the expression is within the allowed grammar
     */
    public static boolean isSafeSpelExpression(String expression) {
        if (expression == null || expression.isEmpty() || expression.length() > 200) {
            return false;
        }
        String rest = SPEL_STRING_LITERAL.matcher(expression).replaceAll("0");
        rest = SPEL_KEYWORDS.matcher(rest).replaceAll(" ");
        return SPEL_REMAINDER.matcher(rest).matches() && !SPEL_BAD_DOT.matcher(rest).find();
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
     * Validate a CORS request Origin against the safe/block domain config ({@link #checkURL(String)}).
     * The value must be a bare origin (scheme://host[:port]) without userinfo, path, query or
     * fragment, and must not contain control characters.
     *
     * @param origin the Origin request header, may be null
     * @return the origin when it is allowed to be echoed in Access-Control-Allow-Origin, otherwise null
     */
    public static String getSafeCorsOrigin(String origin) {
        if (origin == null || origin.isEmpty()) {
            return null;
        }
        for (int i = 0; i < origin.length(); i++) {
            char ch = origin.charAt(i);
            if (Character.isISOControl(ch) || Character.isWhitespace(ch) || ch == '\\') {
                return null;
            }
        }
        URI uri;
        try {
            uri = new URI(origin);
            if (uri.getRawUserInfo() != null || uri.getHost() == null
                    || uri.getRawQuery() != null || uri.getRawFragment() != null) {
                return null;
            }
            String path = uri.getRawPath();
            if (path != null && !path.isEmpty()) {
                return null;
            }
        } catch (URISyntaxException e) {
            return null;
        }
        if (checkURL(origin) == null) {
            return null;
        }

        // Rebuild the origin: fixed scheme literal, the allowlist's own host string when the
        // host is an exact allowlist entry (else the whitelist-rebuilt host), and the port.
        String scheme = "https".equalsIgnoreCase(uri.getScheme()) ? "https" : "http";
        String host = uri.getHost().toLowerCase();
        for (String safeDomain : WebConfig.getSafeDomains()) {
            if (safeDomain != null && safeDomain.equalsIgnoreCase(host)) {
                host = safeDomain.toLowerCase();
                break;
            }
        }
        int port = uri.getPort();
        if (port < -1 || port > 65535) {
            return null;
        }
        String rebuilt = scheme + "://" + host + (port == -1 ? "" : ":" + port);
        String safe = rebuildFromAlphabet(rebuilt, URL_ALPHABET);
        return safe.equals(rebuilt) ? safe : null;
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

        try {
            URI uri = new URI(url);
            if (url.startsWith("/")) {
                // Same-origin path only: no "//host", no scheme, no authority.
                if (url.startsWith("//") || uri.getScheme() != null || uri.getRawAuthority() != null) {
                    return null;
                }
                String path = uri.getRawPath();
                if (path == null || !path.startsWith("/") || path.startsWith("//")
                        || decodeFully(path).startsWith("//")) {
                    return null;
                }
                return appendQueryAndFragment(new StringBuilder(path), uri).toString();
            }

            String scheme = uri.getScheme();
            if (scheme == null || uri.getRawUserInfo() != null || uri.getHost() == null) {
                return null;
            }
            String safeScheme;
            if ("https".equalsIgnoreCase(scheme)) {
                safeScheme = "https";
            } else if ("http".equalsIgnoreCase(scheme)) {
                safeScheme = "http";
            } else {
                return null;
            }
            String host = uri.getHost().toLowerCase();
            if (!SAFE_HOST_PATTERN.matcher(host).matches()) {
                return null;
            }
            int port = uri.getPort();
            if (port < -1 || port > 65535) {
                return null;
            }
            // Allow/block domain config (exact host or proper dot-boundary suffix).
            if (checkURL(safeScheme + "://" + host) == null) {
                return null;
            }

            StringBuilder sb = new StringBuilder(safeScheme).append("://").append(host);
            if (port != -1) {
                sb.append(':').append(port);
            }
            String path = uri.getRawPath();
            if (path != null) {
                sb.append(path);
            }
            return appendQueryAndFragment(sb, uri).toString();
        } catch (URISyntaxException e) {
            return null;
        }
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

    private static StringBuilder appendQueryAndFragment(StringBuilder sb, URI uri) {
        if (uri.getRawQuery() != null) {
            sb.append('?').append(uri.getRawQuery());
        }
        if (uri.getRawFragment() != null) {
            sb.append('#').append(uri.getRawFragment());
        }
        return sb;
    }

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

    public static void main(String[] args) {
    }

}