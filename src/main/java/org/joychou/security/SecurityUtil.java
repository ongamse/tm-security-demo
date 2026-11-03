package org.joychou.security;

import org.joychou.config.WebConfig;
import org.joychou.security.ssrf.SSRFChecker;
import org.joychou.security.ssrf.SocketHook;
import org.joychou.util.WebUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


public class SecurityUtil {

    private static final Pattern FILTER_PATTERN = Pattern.compile("^[a-zA-Z0-9_/\\.-]+$");
    private static final int MAX_CMD_LENGTH = 64;
    private static final Pattern HOST_PORT_PATTERN =
            Pattern.compile("^([a-zA-Z0-9][a-zA-Z0-9.-]*)(?::([0-9]{1,5}))?$");
    private static Logger logger = LoggerFactory.getLogger(SecurityUtil.class);


    /**
     * Determine if the URL starts with HTTP.
     *
     * @param url url
     * @return true or false
     */
    public static boolean isHttp(String url) {
        if (url == null) {
            return false;
        }
        String lower = url.toLowerCase();
        return lower.startsWith("http://") || lower.startsWith("https://");
    }


    /**
     * Get http url host.
     *
     * @param url url
     * @return host
     */
    public static String gethost(String url) {
        HttpUrl parsed = parseHttpUrl(url);
        return parsed == null ? "" : parsed.getHost();
    }


    // Characters allowed in an url path / query / fragment (RFC 3986 pchar + '/' and '?').
    // Backslash, whitespace, control characters and non-ASCII are never accepted.
    private static final String URL_CHARS = "A-Za-z0-9._~!$&'()*+,;=:@%/\\-";
    private static final Pattern HTTP_URL = Pattern.compile(
            "^(https?)://"                                              // 1 scheme (no user info allowed)
            + "(\\[[0-9A-Fa-f:.]+\\]|[A-Za-z0-9][A-Za-z0-9.-]*)"        // 2 host or ipv6 literal
            + "(?::([0-9]{1,5}))?"                                      // 3 port
            + "(/[" + URL_CHARS + "]*)?"                                // 4 path
            + "(?:\\?([" + URL_CHARS + "?]*))?"                         // 5 query
            + "(?:#([" + URL_CHARS + "?]*))?$",                         // 6 fragment
            Pattern.CASE_INSENSITIVE);
    private static final Pattern SAME_SITE_PATH = Pattern.compile(
            "^/(?!/)[" + URL_CHARS + "]*(?:\\?[" + URL_CHARS + "?]*)?(?:#[" + URL_CHARS + "?]*)?$");


    /**
     * An http(s) url that has been strictly parsed. Every component is either a constant
     * (scheme) or matched a restrictive character set, so {@link #toString()} builds a
     * canonical url that is re-constructed from the validated parts and never contains user
     * info, backslashes or control characters.
     */
    public static final class HttpUrl {
        private final String scheme;
        private final String host;
        private final int port;
        private final String path;
        private final String query;
        private final String fragment;

        private HttpUrl(String scheme, String host, int port, String path, String query, String fragment) {
            this.scheme = scheme;
            this.host = host;
            this.port = port;
            this.path = path;
            this.query = query;
            this.fragment = fragment;
        }

        public String getScheme() {
            return scheme;
        }

        /** Lower case host; ipv6 literals keep their brackets. */
        public String getHost() {
            return host;
        }

        /** Port number, or -1 when the url has no explicit port. */
        public int getPort() {
            return port;
        }

        public String getPath() {
            return path;
        }

        public String getQuery() {
            return query;
        }

        public String getFragment() {
            return fragment;
        }

        /** scheme://host[:port] */
        public String origin() {
            return scheme + "://" + host + (port >= 0 ? ":" + port : "");
        }

        /** Canonical url without the fragment (what an http client needs). */
        public String toOutboundString() {
            return origin() + path + (query != null ? "?" + query : "");
        }

        @Override
        public String toString() {
            return toOutboundString() + (fragment != null ? "#" + fragment : "");
        }
    }


    /**
     * Strictly parse an http(s) url. The host cannot differ from what the http client will
     * connect to because only a restrictive grammar is accepted: no user info, no backslash,
     * no whitespace / control characters.
     *
     * @param url the url
     * @return the parsed url, or null when the url is not a well formed http(s) url
     */
    public static HttpUrl parseHttpUrl(String url) {
        if (url == null) {
            return null;
        }
        Matcher m = HTTP_URL.matcher(url);
        if (!m.matches()) {
            return null;
        }
        int port = -1;
        if (m.group(3) != null) {
            port = Integer.parseInt(m.group(3));
            if (port > 65535) {
                return null;
            }
        }
        String scheme = "https".equalsIgnoreCase(m.group(1)) ? "https" : "http";
        String path = m.group(4) == null ? "" : m.group(4);
        return new HttpUrl(scheme, m.group(2).toLowerCase(), port, path, m.group(5), m.group(6));
    }


    /**
     * Validate a user supplied redirect target. Only two forms are accepted:
     * <ul>
     * <li>a same-site absolute path such as <code>/a/b</code> (not <code>//host</code>, no backslash);</li>
     * <li>an http(s) url whose strictly parsed host passes {@link #checkURL(String)}.</li>
     * </ul>
     * Any control character or backslash is rejected.
     *
     * @param url the redirect target
     * @return the original url when safe; null otherwise
     */
    public static String safeRedirectUrl(String url) {
        if (url == null || url.isEmpty()) {
            return null;
        }
        if (url.charAt(0) == '/') {
            // same-site absolute path: rebuilt from a strict server-side alphabet,
            // never "//host" and no backslash.
            return rebuildSameSitePath(url);
        }
        if (checkURL(url) == null) {
            return null;
        }
        return rebuildAllowlistedRedirect(url, WebConfig.getSafeDomains());
    }


    // Server-side alphabets used to re-build redirect targets character by character.
    private static final String REDIRECT_PATH_CHARS =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789/_.~-";
    private static final String REDIRECT_QUERY_CHARS = REDIRECT_PATH_CHARS + "=&%+,";
    private static final String REDIRECT_HOST_LABEL_CHARS = "abcdefghijklmnopqrstuvwxyz0123456789.-";


    /**
     * Re-build a same-site redirect path (optionally with a query) from the server-side alphabets.
     * The result always begins with a single '/' (never "//" or "/\"), contains only characters
     * of the alphabets, and the fragment is dropped.
     *
     * @return the re-built path, or null when the input does not fit (fail closed)
     */
    private static String rebuildSameSitePath(String value) {
        if (value == null || value.isEmpty() || value.charAt(0) != '/') {
            return null;
        }
        if (value.length() > 1 && (value.charAt(1) == '/' || value.charAt(1) == '\\')) {
            return null;
        }
        int q = value.indexOf('?');
        int hash = value.indexOf('#');
        if (hash >= 0 && (q < 0 || hash < q)) {
            return null;
        }
        String rawPath = q < 0 ? value : value.substring(0, q);
        String path = WebUtils.rebuildFromAllowed(rawPath, REDIRECT_PATH_CHARS);
        if (path == null) {
            return null;
        }
        if (q < 0) {
            return path;
        }
        String rawQuery = hash < 0 ? value.substring(q + 1) : value.substring(q + 1, hash);
        String query = WebUtils.rebuildFromAllowed(rawQuery, REDIRECT_QUERY_CHARS);
        if (query == null) {
            return null;
        }
        return path + "?" + query;
    }


    /**
     * Build a redirect target for an absolute http(s) url whose strictly parsed host equals an
     * allowlist entry or is a real subdomain of one. The scheme and the allowlist domain are
     * the server-side strings; only the subdomain label(s) and the path / query are re-built
     * from strict server-side alphabets. The user info, fragment and any other characters are never copied.
     *
     * @return the re-built url, or null when the host is not allowlisted or a component does not fit
     */
    private static String rebuildAllowlistedRedirect(String url, java.util.Collection<String> allowedDomains) {
        HttpUrl parsed = parseHttpUrl(url);
        if (parsed == null || allowedDomains == null) {
            return null;
        }
        String host = parsed.getHost();
        String safeHost = null;
        for (String entry : allowedDomains) {
            if (host.equals(entry)) {
                safeHost = entry;
                break;
            }
            String suffix = "." + entry;
            if (host.endsWith(suffix)) {
                String label = WebUtils.rebuildFromAllowed(
                        host.substring(0, host.length() - suffix.length()), REDIRECT_HOST_LABEL_CHARS);
                if (label == null || label.isEmpty() || label.startsWith(".") || label.startsWith("-")) {
                    return null;
                }
                safeHost = label + suffix;
                break;
            }
        }
        if (safeHost == null) {
            return null;
        }
        StringBuilder sb = new StringBuilder();
        sb.append("https".equals(parsed.getScheme()) ? "https" : "http").append("://").append(safeHost);
        if (parsed.getPort() >= 0) {
            sb.append(':').append(parsed.getPort());
        }
        String path = WebUtils.rebuildFromAllowed(parsed.getPath(), REDIRECT_PATH_CHARS);
        if (path == null) {
            return null;
        }
        sb.append(path);
        if (parsed.getQuery() != null) {
            String query = WebUtils.rebuildFromAllowed(parsed.getQuery(), REDIRECT_QUERY_CHARS);
            if (query == null) {
                return null;
            }
            sb.append('?').append(query);
        }
        return sb.toString();
    }


    /**
     * Return the url only when it is an http(s) url without control characters or backslashes
     * and its strictly parsed host equals one of the domains or is a real subdomain of it
     * (dot boundary).
     *
     * @param url     the redirect target
     * @param domains allowed domains
     * @return the original url when allowed; null otherwise
     */
    public static String redirectUrlIfHostIn(String url, String[] domains) {
        return rebuildAllowlistedRedirect(url, Arrays.asList(domains));
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
            // 必须http/https，并且使用严格解析，返回值由校验后的各部分重新构造
            HttpUrl parsed = parseHttpUrl(url);
            if (parsed == null) {
                return null;
            }
            String host = parsed.getHost();

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
                return parsed.toString();
            }

            // 支持一级域名
            for(String safedomain: safeDomains) {
                if(host.endsWith("." + safedomain)) {
                    return parsed.toString();
                }
            }
            return null;
        } catch (NullPointerException e) {
            logger.error(e.toString());
            return null;
        }
    }


    /**
     * Validate a CORS request Origin header value. The value must be a bare http(s) origin
     * (scheme://host[:port], no user info, path, query or fragment, no control characters or
     * backslashes) whose strictly parsed host is allowed by {@link #checkURL(String)}.
     *
     * @param origin the value of the Origin request header
     * @return the original origin when it is allowed; null otherwise (including the literal "null" origin)
     */
    public static String checkOrigin(String origin) {
        HttpUrl parsed = parseHttpUrl(origin);
        if (parsed == null || !parsed.getPath().isEmpty() || parsed.getQuery() != null
                || parsed.getFragment() != null) {
            return null;
        }
        // bare origin only: must pass the safe / block domain check
        if (checkURL(parsed.origin()) == null) {
            return null;
        }
        return allowlistedOrigin(parsed);
    }


    /**
     * Exact-match CORS allowlist lookup. The Origin request header must be a valid bare origin
     * (see {@link #checkOrigin(String)}) AND equal, character for character, one of the
     * origins built on the server from the configured safe domains (http and https for every
     * entry of url_safe_domain.xml). The returned value is the server-side allowlist entry, never
     * the request string. Sub-domains and other ports are not implicitly trusted.
     *
     * @param origin the value of the Origin request header
     * @return the matching allowlist entry; null when the origin is absent or not allowlisted
     */
    public static String corsAllowedOrigin(String origin) {
        if (origin == null || checkOrigin(origin) == null) {
            return null;
        }
        ArrayList<String> safeDomains = WebConfig.getSafeDomains();
        if (safeDomains == null) {
            return null;
        }
        for (String domain : safeDomains) {
            for (String scheme : new String[]{"https", "http"}) {
                String allowed = scheme + "://" + domain;
                if (allowed.equals(origin)) {
                    return allowed;
                }
            }
        }
        return null;
    }


    private static final String LABEL_CHARS = "abcdefghijklmnopqrstuvwxyz0123456789.-";

    /**
     * Build the value that is written to a CORS response header. The string is constructed on
     * the server: constant scheme literal, the allowlist's own domain entry (looked up from the
     * configured safe domains), a sub-domain prefix re-built from a server-side alphabet and the
     * numeric port. The request's Origin string is never copied.
     */
    private static String allowlistedOrigin(HttpUrl parsed) {
        String host = parsed.getHost();
        String allowedHost = null;
        for (String safeDomain : WebConfig.getSafeDomains()) {
            if (host.equals(safeDomain)) {
                allowedHost = safeDomain;
                break;
            }
        }
        if (allowedHost == null) {
            for (String safeDomain : WebConfig.getSafeDomains()) {
                if (host.endsWith("." + safeDomain)) {
                    String prefix = WebUtils.rebuildFromAllowed(
                            host.substring(0, host.length() - safeDomain.length() - 1), LABEL_CHARS);
                    if (prefix == null || prefix.isEmpty()) {
                        return null;
                    }
                    allowedHost = prefix + "." + safeDomain;
                    break;
                }
            }
        }
        if (allowedHost == null) {
            return null;
        }
        String origin = ("https".equals(parsed.getScheme()) ? "https" : "http") + "://" + allowedHost;
        String origin0 = parsed.origin();
        int portIdx = origin0.lastIndexOf(':');
        // a port is present when the last ':' follows the "://" and the host is not an ipv6 literal
        if (portIdx > origin0.indexOf("://") + 2 && origin0.indexOf(']', portIdx) < 0) {
            try {
                origin = origin + ":" + Integer.parseInt(origin0.substring(portIdx + 1));
            } catch (NumberFormatException e) {
                return null;
            }
        }
        return origin;
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
                logger.info("Unsupported encoding exception: " + WebUtils.sanitizeLog(filepath));
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
        if (input == null || !FILTER_PATTERN.matcher(input).matches()) {
            return null;
        }

        return input;
    }


    /**
     * Map a user supplied command line to one of a fixed set of server-defined argv arrays that is
     * safe to pass to ProcessBuilder / Runtime.exec(String[]) without a shell. The user text is only
     * used as a selector: the returned argv is always built from constants, never from the input.
     *
     * @param cmd the user supplied command line
     * @return a constant argv array, or null if the command is not in the allowlist
     */
    public static String[] cmdToArgv(String cmd) {
        if (cmd == null || cmd.length() > MAX_CMD_LENGTH) {
            return null;
        }
        switch (cmd.trim().replaceAll("\\s+", " ")) {
            case "whoami":
                return new String[]{"whoami"};
            case "id":
                return new String[]{"id"};
            case "id -u":
                return new String[]{"id", "-u"};
            case "id -un":
                return new String[]{"id", "-un"};
            case "hostname":
                return new String[]{"hostname"};
            case "uname":
                return new String[]{"uname"};
            case "uname -a":
                return new String[]{"uname", "-a"};
            case "uname -s":
                return new String[]{"uname", "-s"};
            case "uname -r":
                return new String[]{"uname", "-r"};
            case "date":
                return new String[]{"date"};
            case "pwd":
                return new String[]{"pwd"};
            default:
                return null;
        }
    }


    /**
     * Build a constant "ls -la -- path" argv for a path below the server temp directory. The user
     * text is only a selector: every path segment is matched against the real directory entries
     * returned by the file system and the argv is built from those entries, never from the input.
     * Absolute paths, "..", and symlinks that leave the base directory are rejected.
     *
     * @param filepath user supplied path (relative to, or inside, the temp directory)
     * @return argv array, or null if the path is not allowed
     */
    public static String[] lsArgv(String filepath) {
        if (cmdFilter(filepath) == null) {
            return null;
        }
        try {
            File base = new File(System.getProperty("java.io.tmpdir")).getCanonicalFile();
            String basePath = base.getPath();
            String relative = filepath;
            if (relative.equals(basePath)) {
                relative = "";
            } else if (relative.startsWith(basePath + File.separator)) {
                relative = relative.substring(basePath.length() + 1);
            } else if (relative.startsWith("/")) {
                return null;
            }
            File current = base;
            for (String segment : relative.split("/")) {
                if (segment.isEmpty() || segment.equals(".")) {
                    continue;
                }
                if (segment.equals("..")) {
                    return null;
                }
                String[] names = current.list();
                if (names == null) {
                    return null;
                }
                File next = null;
                for (String name : names) {
                    if (name.equals(segment)) {
                        next = new File(current, name);
                        break;
                    }
                }
                if (next == null) {
                    return null;
                }
                current = next;
            }
            String canonical = current.getCanonicalPath();
            if (!canonical.equals(basePath) && !canonical.startsWith(basePath + File.separator)) {
                return null;
            }
            return new String[]{"ls", "-la", "--", canonical};
        } catch (IOException e) {
            return null;
        }
    }


    /**
     * Build a constant "curl -- url" argv for a Host header value. The header is only a selector:
     * the host must equal one of the configured safe domains (the configured value is used, never the
     * header text), must only resolve to public addresses, and an optional port is re-built from a
     * parsed integer.
     *
     * @param hostHeader the Host header value
     * @return argv array, or null if the host is not allowed
     */
    public static String[] curlArgv(String hostHeader) {
        if (hostHeader == null) {
            return null;
        }
        Matcher m = HOST_PORT_PATTERN.matcher(hostHeader);
        if (!m.matches()) {
            return null;
        }
        String host = m.group(1);
        ArrayList<String> safeDomains = WebConfig.getSafeDomains();
        if (safeDomains == null) {
            return null;
        }
        String allowed = null;
        for (String domain : safeDomains) {
            if (domain.equalsIgnoreCase(host)) {
                allowed = domain;
                break;
            }
        }
        if (allowed == null || !SSRFChecker.isSafeOutboundHost(allowed)) {
            return null;
        }
        StringBuilder target = new StringBuilder("http://").append(allowed);
        if (m.group(2) != null) {
            int port = Integer.parseInt(m.group(2));
            if (port < 1 || port > 65535) {
                return null;
            }
            target.append(':').append(port);
        }
        return new String[]{"curl", "--max-time", "10", "--proto", "=http,https", "--", target.toString()};
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