package org.joychou.security;

import org.joychou.config.WebConfig;
import org.joychou.security.ssrf.SSRFChecker;
import org.joychou.security.ssrf.SSRFException;
import org.joychou.security.ssrf.SocketHook;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.URLDecoder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


public class SecurityUtil {

    private static final Pattern FILTER_PATTERN = Pattern.compile("^[a-zA-Z0-9_/\\.-]+$");
    private static final Pattern JDBC_URL_PATTERN = Pattern.compile(
            "^jdbc:(postgresql|db2)://([A-Za-z0-9][A-Za-z0-9.-]*)(:[0-9]{1,5})?(/[A-Za-z0-9_.-]*)?$");
    private static final Pattern RELATIVE_PATH_PATTERN = Pattern.compile(
            "^/(?:%[0-9A-Fa-f]{2}|[A-Za-z0-9._~!$&'()*+,;=:@/?#-])*$");
    // allowlist: request-supplied name -> literal executable name (resolved by name only, no path component)
    private static final Map<String, String> ALLOWED_COMMANDS = new HashMap<>();
    static {
        ALLOWED_COMMANDS.put("whoami", "whoami");
        ALLOWED_COMMANDS.put("id", "id");
        ALLOWED_COMMANDS.put("pwd", "pwd");
        ALLOWED_COMMANDS.put("date", "date");
        ALLOWED_COMMANDS.put("uname", "uname");
        ALLOWED_COMMANDS.put("hostname", "hostname");
        ALLOWED_COMMANDS.put("ls", "ls");
    }
    // allowlist: request-supplied option -> literal ls option
    private static final Map<String, String> ALLOWED_LS_OPTIONS = new HashMap<>();
    static {
        ALLOWED_LS_OPTIONS.put("-l", "-l");
        ALLOWED_LS_OPTIONS.put("-a", "-a");
        ALLOWED_LS_OPTIONS.put("-la", "-la");
        ALLOWED_LS_OPTIONS.put("-al", "-al");
        ALLOWED_LS_OPTIONS.put("-lh", "-lh");
        ALLOWED_LS_OPTIONS.put("-lah", "-lah");
    }
    // allowlist: request-supplied directory -> literal directory
    private static final Map<String, String> ALLOWED_DIRECTORIES = new HashMap<>();
    static {
        ALLOWED_DIRECTORIES.put("/tmp", "/tmp");
        ALLOWED_DIRECTORIES.put("/var/tmp", "/var/tmp");
        ALLOWED_DIRECTORIES.put(".", ".");
    }
    private static Logger logger = LoggerFactory.getLogger(SecurityUtil.class);


    /**
     * Determine if the URL starts with HTTP.
     *
     * @param url url
     * @return true or false
     */
    public static boolean isHttp(String url) {
        if (null == url) {
            return false;
        }
        String lower = url.toLowerCase();
        return lower.startsWith("http://") || lower.startsWith("https://");
    }


    /**
     * Validate an untrusted JDBC url. Only <code>jdbc:&lt;subprotocol&gt;://host[:port][/database]</code>
     * is accepted: no query string, matrix parameters or other driver properties (which can load
     * arbitrary classes, e.g. CVE-2022-21724), and the host must resolve to public addresses only.
     *
     * @param jdbcUrl     untrusted jdbc url
     * @param subprotocol expected jdbc subprotocol, e.g. postgresql or db2
     * @return true if the url is safe to hand to the driver
     */
    public static boolean isSafeJdbcUrl(String jdbcUrl, String subprotocol) {
        try {
            requireSafeJdbcUrl(jdbcUrl, subprotocol);
            return true;
        } catch (IllegalArgumentException | SSRFException e) {
            logger.error("Jdbc url rejected by validation");
            return false;
        }
    }


    /**
     * The chokepoint for every untrusted JDBC url. The url is matched against a strict allowlist
     * pattern (only the given subprotocol, plain host, optional port and database name), the host is
     * resolved and must be public, and the returned url is <b>rebuilt</b> from the validated parts with
     * the validated IP address instead of the host name, so the driver connects to the address that
     * was checked (no DNS rebinding). Callers must pass only the returned value to
     * {@code DriverManager.getConnection}.
     *
     * @param jdbcUrl     untrusted jdbc url
     * @param subprotocol expected jdbc subprotocol, e.g. postgresql or db2
     * @return the validated jdbc url
     * @throws IllegalArgumentException if the url is not allowed
     * @throws SSRFException            if the host is not a public address
     */
    public static String requireSafeJdbcUrl(String jdbcUrl, String subprotocol) {
        if (null == jdbcUrl || null == subprotocol) {
            throw new IllegalArgumentException("Illegal jdbc url");
        }
        Matcher m = JDBC_URL_PATTERN.matcher(jdbcUrl);
        if (!m.matches() || !subprotocol.equals(m.group(1))) {
            throw new IllegalArgumentException("Illegal jdbc url");
        }
        // driver prefix: a literal chosen by comparing against the allowlisted sub-protocols
        String prefix;
        if ("postgresql".equals(subprotocol)) {
            prefix = "jdbc:postgresql://";
        } else if ("db2".equals(subprotocol)) {
            prefix = "jdbc:db2://";
        } else {
            throw new IllegalArgumentException("Illegal jdbc url");
        }
        int port = -1;
        if (null != m.group(3)) {
            port = Integer.parseInt(m.group(3).substring(1));  // ":NNNNN", digits only by the pattern
            if (port < 1 || port > 65535) {
                throw new IllegalArgumentException("Illegal jdbc url");
            }
        }
        // the host is replaced by the validated (public) address the driver will connect to
        String host = SSRFChecker.pinnedHostLiteral(SSRFChecker.resolveSafeAddresses(m.group(2)));
        return prefix + host
                + (port < 0 ? "" : ":" + port)
                + (null == m.group(4) ? "" : m.group(4));
    }


    /**
     * Get http url host. Only absolute http/https urls have a host, see
     * {@link SSRFChecker#parseHttpUrl(String)}.
     *
     * @param url url
     * @return host (lower case), or "" when the url is not a well-formed http(s) url
     */
    public static String gethost(String url) {
        SSRFChecker.HttpUrl parsed = SSRFChecker.parseHttpUrl(url);
        if (null == parsed) {
            return "";
        }
        return parsed.getHost();
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
            logger.error("Safe domain check failed with a NullPointerException");
            return null;
        }
    }


    /**
     * Strict syntax check of an absolute http(s) url: no whitespace/control characters, no backslash,
     * matching the strict RFC 3986 http(s) pattern, non-empty host and no userinfo ("user@host" tricks).
     *
     * @param url untrusted url
     * @return true if the url is a well-formed http/https url with a plain host
     */
    public static boolean isSafeHttpUrl(String url) {
        if (!isHttp(url) || hasUnsafeRedirectChars(url)) {
            return false;
        }
        SSRFChecker.HttpUrl parsed = SSRFChecker.parseHttpUrl(url);
        return null != parsed && !parsed.getHost().isEmpty() && null == parsed.getRawUserInfo();
    }


    /**
     * Validate an untrusted redirect destination. Accepts either a same-origin relative path
     * (single leading "/", never "//host" or "/\host") or an absolute http/https url whose host is
     * allowed by {@link #checkURL(String)}.
     *
     * @param url untrusted redirect destination
     * @return the url when it is a safe destination; null otherwise
     */
    public static String safeRedirectUrl(String url) {
        if (null == url || url.isEmpty() || hasUnsafeRedirectChars(url)) {
            return null;
        }
        if (url.startsWith("/")) {
            // single leading "/" followed by RFC 3986 path/query/fragment characters only
            // (no scheme, no authority, no backslash, no whitespace/control characters)
            if (url.startsWith("//") || !RELATIVE_PATH_PATTERN.matcher(url).matches()) {
                return null;
            }
            return url;
        }
        if (isSafeHttpUrl(url) && null != checkURL(url)) {
            return url;
        }
        return null;
    }


    /**
     * Same validation as {@link #safeRedirectUrl(String)}, but never returns null: an unsafe
     * destination is replaced by the fixed same-origin path "/".
     *
     * @param url untrusted redirect destination
     * @return a validated destination, or "/" when validation fails
     */
    public static String safeRedirectUrlOrRoot(String url) {
        String safe = safeRedirectUrl(url);
        return null == safe ? "/" : safe;
    }


    private static boolean hasUnsafeRedirectChars(String url) {
        for (int i = 0; i < url.length(); i++) {
            char ch = url.charAt(i);
            if (ch <= 0x20 || ch == 0x7f || ch == '\\' || ch == 0x2028 || ch == 0x2029) {
                return true;
            }
        }
        return false;
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
                logger.info("Unsupported encoding exception while decoding file path, length: {}", filepath.length());
                return null;
            } catch (Exception e) {
                logger.info("Decoding file path failed, error type: {}", e.getClass().getSimpleName());
                return null;
            }
        }

        if (temp.contains("..") || temp.charAt(0) == '/') {
            return null;
        }

        return filepath;
    }


    /**
     * Make an untrusted value safe to place in an HTTP header (prevents CRLF / response splitting).
     * Removes CR, LF and all other ISO control characters (horizontal tab is kept) and U+2028/U+2029.
     *
     * @param value untrusted header value, may be null
     * @return the value without control characters, or null when the input is null
     */
    public static String safeHeaderValue(String value) {
        if (null == value) {
            return null;
        }
        // strip CR, LF, every other ISO control char (keep \t) and the Unicode line/paragraph separators
        return value.replaceAll("[\\x00-\\x08\\x0A-\\x1F\\x7F-\\x9F\\u2028\\u2029]", "");
    }

    /**
     * Make an untrusted value safe to use as a cookie value (prevents CRLF injection and cookie splitting).
     * Removes control characters (see {@link #safeHeaderValue(String)}) and the characters that are not
     * allowed in a cookie value: whitespace, double quote, comma, semicolon and backslash.
     *
     * @param value untrusted cookie value, may be null
     * @return the cleaned value, or null when the input is null
     */
    public static String safeCookieValue(String value) {
        String cleaned = safeHeaderValue(value);
        if (null == cleaned) {
            return null;
        }
        return cleaned.replaceAll("[\\s\",;\\\\]", "");
    }


    /**
     * Validate a request Origin header against the trusted-domain list used by {@link #checkURL(String)}.
     * Only a plain <code>scheme://host[:port]</code> origin (no userinfo, path, query or fragment) whose
     * host is allowed is accepted. Callers must emit Access-Control-Allow-Origin only for a non-null result.
     *
     * @param origin untrusted Origin header value, may be null
     * @return the origin when it is trusted; null otherwise (including for the literal "null" origin)
     */
    public static String safeCorsOrigin(String origin) {
        if (null == origin || !isSafeHttpUrl(origin) || null == checkURL(origin)) {
            return null;
        }
        SSRFChecker.HttpUrl parsed = SSRFChecker.parseHttpUrl(origin);
        if (null == parsed) {
            return null;
        }
        String path = parsed.getRawPath();
        if ((null != path && !path.isEmpty()) || null != parsed.getRawQuery() || null != parsed.getRawFragment()) {
            return null;
        }
        return safeHeaderValue(origin);
    }


    /**
     * Fixed allowlist of origins that may receive CORS (including credentialed) responses.
     */
    private static final List<String> CORS_ALLOWED_ORIGINS = Collections.unmodifiableList(Arrays.asList(
            "https://joychou.org",
            "https://joychou.com",
            "https://test.joychou.org",
            "https://test.joychou.me",
            "http://localhost:8080"));


    /**
     * Look the request Origin up in the fixed {@link #CORS_ALLOWED_ORIGINS} allowlist. The returned value is
     * always the constant allowlist element, never the request string, so it is safe to emit as
     * Access-Control-Allow-Origin (and alongside Access-Control-Allow-Credentials).
     *
     * @param requestOrigin untrusted Origin header value, may be null
     * @return the matching allowlist element, or null when the origin is not allowlisted (incl. "null" and "*")
     */
    public static String allowedCorsOrigin(String requestOrigin) {
        if (null == requestOrigin) {
            return null;
        }
        for (String allowed : CORS_ALLOWED_ORIGINS) {
            if (allowed.equalsIgnoreCase(requestOrigin)) {
                return allowed;
            }
        }
        return null;
    }


    /**
     * @return a copy of the explicit CORS origin allowlist, for framework CORS registrations
     */
    public static String[] corsAllowedOrigins() {
        return CORS_ALLOWED_ORIGINS.toArray(new String[0]);
    }


    public static String cmdFilter(String input) {
        if (null == input || !FILTER_PATTERN.matcher(input).matches()) {
            return null;
        }

        return input;
    }


    /**
     * Look an untrusted directory up in a fixed allowlist.
     *
     * @param dir untrusted directory
     * @return the matching allowlist literal (never the request string), or null when not allowlisted
     */
    public static String allowedDirectory(String dir) {
        if (null == dir) {
            return null;
        }
        return literalOf(ALLOWED_DIRECTORIES, dir);
    }


    /**
     * Return the allowlist's own constant that equals the request value (never the request string itself).
     */
    private static String literalOf(Map<String, String> allowlist, String requested) {
        for (Map.Entry<String, String> entry : allowlist.entrySet()) {
            if (entry.getKey().equals(requested)) {
                return entry.getValue();
            }
        }
        return null;
    }


    /**
     * Turn an untrusted <code>host[:port]</code> (e.g. a Host header) into a canonical http url that is
     * <b>rebuilt</b> from parsed parts: the host must be allowed by {@link #checkURL(String)}, must resolve to
     * public addresses only, and is replaced by its resolved IP address; the port is re-rendered from the
     * parsed integer. The request string itself is never part of the result.
     *
     * @param hostPort untrusted host and optional port
     * @return canonical <code>http://ip[:port]</code> url, or null when the value is not acceptable
     */
    public static String canonicalHostUrl(String hostPort) {
        if (null == hostPort || null == checkURL("http://" + hostPort)) {
            return null;
        }
        String hostPart = hostPort;
        int port = -1;
        int colon = hostPort.lastIndexOf(':');
        if (colon >= 0) {
            hostPart = hostPort.substring(0, colon);
            try {
                port = Integer.parseInt(hostPort.substring(colon + 1));
            } catch (NumberFormatException e) {
                return null;
            }
            if (port < 1 || port > 65535) {
                return null;
            }
        }
        try {
            InetAddress[] addresses = SSRFChecker.resolveSafeAddresses(hostPart);
            InetAddress pinned = addresses[0];
            for (InetAddress address : addresses) {
                if (address instanceof Inet4Address) {
                    pinned = address;
                    break;
                }
            }
            String ip = pinned.getHostAddress();
            if (pinned instanceof Inet6Address) {
                int scope = ip.indexOf('%');
                ip = "[" + (scope < 0 ? ip : ip.substring(0, scope)) + "]";
            }
            return "http://" + ip + (port < 0 ? "" : ":" + port);
        } catch (SSRFException e) {
            logger.error("Host url rejected by validation");
            return null;
        }
    }


    /**
     * Map an untrusted command line to a literal argv array for a shell-less process start.
     * Every element of the returned array is a constant taken from a fixed allowlist (executable name,
     * ls option or directory); no part of the request string is ever copied into the result.
     * Only "ls" accepts arguments.
     *
     * @param cmd untrusted command line, e.g. "ls -la /tmp"
     * @return argv array of allowlist literals, or null if the command is empty, not allowlisted,
     *         or has an argument that is not allowlisted
     */
    public static String[] allowedCommand(String cmd) {
        if (null == cmd || cmd.trim().isEmpty()) {
            return null;
        }
        String[] parts = cmd.trim().split("\\s+");
        String executable = literalOf(ALLOWED_COMMANDS, parts[0]);
        if (null == executable) {
            return null;
        }
        String[] argv = new String[parts.length];
        argv[0] = executable;
        for (int i = 1; i < parts.length; i++) {
            if (!"ls".equals(executable)) {
                return null;
            }
            String literal = literalOf(ALLOWED_LS_OPTIONS, parts[i]);
            if (null == literal) {
                literal = literalOf(ALLOWED_DIRECTORIES, parts[i]);
            }
            if (null == literal) {
                return null;
            }
            argv[i] = literal;
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