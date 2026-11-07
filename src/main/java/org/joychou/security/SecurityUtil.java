package org.joychou.security;

import org.joychou.config.WebConfig;
import org.joychou.security.ssrf.SSRFChecker;
import org.joychou.security.ssrf.SocketHook;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLDecoder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


public class SecurityUtil {

    private static final Pattern FILTER_PATTERN = Pattern.compile("^[a-zA-Z0-9_/\\.-]+$");
    private static Logger logger = LoggerFactory.getLogger(SecurityUtil.class);

    // Host part of an http(s) url: plain host name / IPv4 only (no userinfo, no backslash, no IPv6 literal).
    private static final Pattern HTTP_HOST_PATTERN = Pattern.compile(
            "^https?://([A-Za-z0-9.-]+)(?::[0-9]{1,5})?(?:[/?#].*)?$");

    private static final int MAX_URL_LENGTH = 2048;

    // Outbound url: scheme, host, optional port, path (unreserved characters and '/'), optional query.
    private static final Pattern ALLOWED_URL_PATTERN = Pattern.compile(
            "^(https?)://([A-Za-z0-9.-]{1,253})(?::([0-9]{1,5}))?(/[A-Za-z0-9._~/-]*)?(?:\\?([A-Za-z0-9._~=&-]*))?$");

    // A same-origin redirect path (single leading slash) or an absolute http(s) redirect url.
    // No control characters, whitespace, backslash, userinfo or non-ASCII characters can match.
    private static final String REDIRECT_CHARS = "[A-Za-z0-9._~!$&'()*+,;=:@/?#%\\[\\]-]*";
    private static final Pattern REDIRECT_PATH_PATTERN = Pattern.compile("^(/(?!/)" + REDIRECT_CHARS + ")$");
    private static final Pattern REDIRECT_ABSOLUTE_PATTERN = Pattern.compile(
            "^(https?)://([A-Za-z0-9.-]+)(?::([0-9]{1,5}))?([/?#]" + REDIRECT_CHARS + ")?$");


    /**
     * Determine if the URL starts with HTTP.
     *
     * @param url url
     * @return true or false
     */
    public static boolean isHttp(String url) {
        return url != null && (url.startsWith("http://") || url.startsWith("https://"));
    }


    /**
     * Get http url host.
     *
     * @param url url
     * @return host
     */
    public static String gethost(String url) {
        if (url == null) {
            return "";
        }
        // Strict host extraction; urls with userinfo, backslashes, control characters or an IPv6
        // literal do not match and yield "" (fail closed).
        Matcher m = HTTP_HOST_PATTERN.matcher(url);
        return m.matches() ? m.group(1).toLowerCase(Locale.ROOT) : "";
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
        return resolveAllowedUrl(url) != null;
    }

    /**
     * Single choke-point for every server side outbound request made on behalf of a user supplied url.
     * <p>
     * The raw string is only parsed, never used: the returned {@link URL} is rebuilt from
     * <ul>
     *   <li>a constant scheme (<code>http</code> or <code>https</code>),</li>
     *   <li>the host taken from the server side allowlist (<code>ssrf_safe_domain.xml</code>, exact,
     *       case-insensitive match; subdomains are not implied),</li>
     *   <li>an optional port that must be 80 or 443,</li>
     *   <li>a path made of unreserved characters only without <code>.</code>/<code>..</code> segments
     *       and an optional plain <code>key=value&amp;...</code> query (no userinfo, fragment, backslash,
     *       whitespace or control characters can match).</li>
     * </ul>
     * and every address the allowlisted host resolves to must still be public. Fails closed: an empty
     * allowlist rejects everything. Callers must disable redirects and set timeouts on their client.
     *
     * @param rawUrl url supplied by the user
     * @return the rebuilt url; null when the url is not allowed
     */
    public static URL resolveAllowedUrl(String rawUrl) {
        if (rawUrl == null || rawUrl.length() > MAX_URL_LENGTH) {
            return null;
        }
        Matcher m = ALLOWED_URL_PATTERN.matcher(rawUrl);
        if (!m.matches()) {
            return null;
        }
        String scheme = "https".equalsIgnoreCase(m.group(1)) ? "https" : "http";

        // exact match against the server side allowlist; the host that is used comes from the allowlist
        String allowedHost = allowlistedPublicHost(m.group(2));
        if (allowedHost == null) {
            return null;
        }

        int port = -1;
        if (m.group(3) != null) {
            int requestedPort = Integer.parseInt(m.group(3));
            if (requestedPort != 80 && requestedPort != 443) {
                return null;
            }
            port = requestedPort;
        }

        String path = m.group(4) == null ? "" : m.group(4);
        for (String segment : path.split("/", -1)) {
            if (".".equals(segment) || "..".equals(segment)) {
                return null;
            }
        }
        String query = m.group(5);

        try {
            return new URI(scheme, null, allowedHost, port, path, query, null).toURL();
        } catch (URISyntaxException | MalformedURLException | IllegalArgumentException e) {
            logger.error("Illegal outbound url rejected: " + e.getClass().getSimpleName());
            return null;
        }
    }


    /**
     * Validate a request derived value before it is written into an HTTP response header.
     * Any ASCII control character (CR, LF, NUL, ...) except horizontal tab, and DEL, is rejected
     * so that the value cannot split the response (CWE-113).
     *
     * @param value candidate header value
     * @return the original value when it is safe; null when it is null or contains control characters
     */
    public static String safeHeaderValue(String value) {
        if (value == null) {
            return null;
        }
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if ((c < 0x20 && c != '\t') || c == 0x7f) {
                return null;
            }
        }
        return value;
    }


    /**
     * Look up a request Origin in the fixed server side CORS allowlist
     * (<code>joychou.security.cors.allowed-origins</code>, exact match) and return the matching
     * constant element of that allowlist. The request string itself is never returned, so the value
     * written to Access-Control-Allow-Origin always comes from server configuration. An empty
     * allowlist rejects everything (fail closed).
     *
     * @param origin value of the request Origin header
     * @return the allowlisted origin; null when not allowlisted (including a null origin or "null")
     */
    public static String safeCorsOrigin(String origin) {
        if (origin == null || safeHeaderValue(origin) == null) {
            return null;
        }
        for (String allowed : WebConfig.getCorsAllowedOrigins()) {
            if (allowed.equals(origin)) {
                return allowed;
            }
        }
        return null;
    }


    /**
     * Validate a user supplied redirect target (CWE-601). Fails closed.
     * Accepted targets are either a same-origin relative path (single leading slash, no
     * "//" or backslash tricks) or an absolute http/https url whose host is allowed by
     * {@link #checkURL(String)}, has no userinfo, and is parsed identically by java.net.URI and
     * java.net.URL. Any control character (CR, LF, ...) is rejected.
     * The returned value is rebuilt from the validated parts (constant scheme, lower-cased allowlisted
     * host, port digits and the tail that matched a strict character class), never the raw string.
     *
     * @param url candidate redirect target
     * @return the rebuilt, equivalent url when safe; null otherwise
     */
    public static String safeRedirectUrl(String url) {
        if (url == null || url.length() > MAX_URL_LENGTH || safeHeaderValue(url) == null
                || url.indexOf('\\') >= 0) {
            return null;
        }
        if (url.startsWith("/")) {
            // same-origin path only: the pattern rejects "//host", a scheme, userinfo and backslashes
            Matcher pm = REDIRECT_PATH_PATTERN.matcher(url);
            return pm.matches() ? pm.group(1) : null;
        }
        // The host group excludes userinfo, backslashes and every other delimiter, and is followed
        // directly by an optional port and the tail, so URI/URL parser differentials cannot occur.
        Matcher m = REDIRECT_ABSOLUTE_PATTERN.matcher(url);
        if (!m.matches() || checkURL(url) == null) {
            return null;
        }
        String scheme = "https".equals(m.group(1)) ? "https" : "http";
        return scheme + "://" + m.group(2).toLowerCase(Locale.ROOT)
                + (m.group(3) != null ? ":" + m.group(3) : "")
                + (m.group(4) != null ? m.group(4) : "");
    }


    private static final Pattern JDBC_AUTHORITY_PATTERN = Pattern.compile(
            "^([A-Za-z0-9.-]{1,253})(?::([0-9]{1,5}))?$");
    private static final Pattern JDBC_DB_PATTERN = Pattern.compile("^[A-Za-z0-9_.-]*$");
    private static final Pattern JDBC_VALUE_PATTERN = Pattern.compile("^[A-Za-z0-9._@-]*$");
    private static final Set<String> POSTGRESQL_JDBC_PARAMS = new HashSet<>(Arrays.asList(
            "user", "password", "ssl", "sslmode", "connectTimeout", "loginTimeout",
            "socketTimeout", "ApplicationName", "currentSchema"));
    private static final Set<String> DB2_JDBC_PARAMS = new HashSet<>(Arrays.asList(
            "user", "password", "sslConnection", "loginTimeout", "connectionTimeout", "currentSchema"));

    /**
     * Resolve a requested host against the server side allowlist (exact, case-insensitive match).
     *
     * @return the host as written in the allowlist when it is allowed and every address it resolves
     * to is public; null otherwise (an empty allowlist rejects everything)
     */
    private static String allowlistedPublicHost(String requestedHost) {
        if (requestedHost == null) {
            return null;
        }
        String wanted = requestedHost.toLowerCase(Locale.ROOT);
        for (String candidate : WebConfig.getSsrfSafeDomains()) {
            if (candidate == null) {
                continue;
            }
            String allowed = candidate.trim().toLowerCase(Locale.ROOT);
            if (allowed.equals(wanted)) {
                return SSRFChecker.isInternalIpByUrl("http://" + allowed + "/") ? null : allowed;
            }
        }
        return null;
    }

    /**
     * Parse the host:port authority of a jdbc url and rebuild it from the allowlisted host and the
     * numeric port.
     *
     * @return rebuilt authority; null when not allowed
     */
    private static String rebuildJdbcAuthority(String authority) {
        // only plain host names / ipv4 are accepted (no ipv6 literal, no userinfo)
        Matcher m = JDBC_AUTHORITY_PATTERN.matcher(authority);
        if (!m.matches()) {
            return null;
        }
        String host = allowlistedPublicHost(m.group(1));
        if (host == null) {
            return null;
        }
        if (m.group(2) == null) {
            return host;
        }
        int port = Integer.parseInt(m.group(2));
        return port >= 1 && port <= 65535 ? host + ":" + port : null;
    }

    /**
     * Validate <code>key=value</code> pairs: the key must be allowlisted and the value a plain token.
     *
     * @return the rebuilt pairs joined by the separator; null when a pair is not allowed
     */
    private static String rebuildJdbcPairs(String pairs, String separator, Set<String> allowedKeys) {
        StringBuilder out = new StringBuilder();
        for (String pair : pairs.split(Pattern.quote(separator), -1)) {
            if (pair.isEmpty() && ";".equals(separator)) {
                continue; // trailing ';'
            }
            int eq = pair.indexOf('=');
            String key = eq < 0 ? pair : pair.substring(0, eq);
            String value = eq < 0 ? "" : pair.substring(eq + 1);
            if (!allowedKeys.contains(key) || !JDBC_VALUE_PATTERN.matcher(value).matches()) {
                return null;
            }
            if (out.length() > 0) {
                out.append(separator);
            }
            out.append(key).append('=').append(value);
        }
        return out.toString();
    }

    /**
     * Rebuild <code>jdbc:postgresql://host[:port]/db[?key=value&amp;...]</code> from allowlisted parts.
     * The host must be allowlisted and public, and only plain connection parameters are allowed, so that
     * parameters which load classes (socketFactory, sslfactory, authenticationPluginClassName, ...) are
     * rejected. The returned value, not the raw string, must be passed to the driver.
     *
     * @return the rebuilt jdbc url; null when not allowed
     */
    public static String resolveAllowedPostgresqlJdbcUrl(String jdbcUrl) {
        String prefix = "jdbc:postgresql://";
        if (jdbcUrl == null || jdbcUrl.length() > MAX_URL_LENGTH || !jdbcUrl.startsWith(prefix)) {
            return null;
        }
        String rest = jdbcUrl.substring(prefix.length());
        String query = null;
        int q = rest.indexOf('?');
        if (q >= 0) {
            query = rest.substring(q + 1);
            rest = rest.substring(0, q);
        }
        int slash = rest.indexOf('/');
        if (slash < 0) {
            return null;
        }
        String authority = rebuildJdbcAuthority(rest.substring(0, slash));
        String db = rest.substring(slash + 1);
        if (authority == null || !JDBC_DB_PATTERN.matcher(db).matches()) {
            return null;
        }
        StringBuilder out = new StringBuilder(prefix).append(authority).append('/').append(db);
        if (query != null && !query.isEmpty()) {
            String pairs = rebuildJdbcPairs(query, "&", POSTGRESQL_JDBC_PARAMS);
            if (pairs == null) {
                return null;
            }
            out.append('?').append(pairs);
        }
        return out.toString();
    }

    /**
     * Rebuild <code>jdbc:db2://host[:port]/db[:key=value;...;]</code> from allowlisted parts.
     * The host must be allowlisted and public, and only plain connection properties are allowed.
     *
     * @return the rebuilt jdbc url; null when not allowed
     */
    public static String resolveAllowedDb2JdbcUrl(String jdbcUrl) {
        String prefix = "jdbc:db2://";
        if (jdbcUrl == null || jdbcUrl.length() > MAX_URL_LENGTH || !jdbcUrl.startsWith(prefix)) {
            return null;
        }
        String rest = jdbcUrl.substring(prefix.length());
        int slash = rest.indexOf('/');
        if (slash < 0) {
            return null;
        }
        String authority = rebuildJdbcAuthority(rest.substring(0, slash));
        String dbAndProps = rest.substring(slash + 1);
        String props = "";
        int colon = dbAndProps.indexOf(':');
        if (colon >= 0) {
            props = dbAndProps.substring(colon + 1);
            dbAndProps = dbAndProps.substring(0, colon);
        }
        if (authority == null || !JDBC_DB_PATTERN.matcher(dbAndProps).matches()) {
            return null;
        }
        StringBuilder out = new StringBuilder(prefix).append(authority).append('/').append(dbAndProps);
        if (!props.isEmpty()) {
            String pairs = rebuildJdbcPairs(props, ";", DB2_JDBC_PARAMS);
            if (pairs == null) {
                return null;
            }
            if (!pairs.isEmpty()) {
                out.append(':').append(pairs).append(';');
            }
        }
        return out.toString();
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