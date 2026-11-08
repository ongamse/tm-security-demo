package org.joychou.security;

import org.joychou.config.WebConfig;
import org.joychou.security.ssrf.ParsedUrl;
import org.joychou.security.ssrf.SSRFChecker;
import org.joychou.security.ssrf.SocketHook;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Pattern;


public class SecurityUtil {

    private static final Pattern FILTER_PATTERN = Pattern.compile("^[a-zA-Z0-9_/\\.-]+$");
    private static final Pattern CMD_ARG_PATTERN = Pattern.compile("^[a-zA-Z0-9_/\\.=-]+$");
    private static final Set<String> CMD_ALLOWLIST = new HashSet<>(
            Arrays.asList("whoami", "id", "date", "hostname", "uname", "pwd", "uptime", "ls"));
    private static final Set<String> JDBC_SUBPROTOCOLS = new HashSet<>(Arrays.asList("postgresql", "db2"));
    private static final Set<String> JDBC_PORTS = new HashSet<>(Arrays.asList("5432", "5433", "50000", "50001"));
    private static final Pattern JDBC_DB_NAME_PATTERN = Pattern.compile("^[A-Za-z0-9_-]{1,63}$");
    private static Logger logger = LoggerFactory.getLogger(SecurityUtil.class);

    private static final String HEADER_VALUE_CHARS =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 _.,:=@/+-";
    private static final String COOKIE_VALUE_CHARS =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.:=@/+-";
    private static final String FILENAME_CHARS =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-";
    private static final String HOST_CHARS = "abcdefghijklmnopqrstuvwxyz0123456789.-";
    private static final String URL_CHARS =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._~!$&'()*+,;=:@/?#%-";
    private static final int MAX_URL_LENGTH = 2048;
    private static final List<String> SCHEMES = Collections.unmodifiableList(Arrays.asList("http", "https"));


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
        if (url == null || !isHttp(url)) {
            return "";
        }
        // Strict authority parsing (no userinfo / odd characters); the raw string never reaches URI/URL.
        return ParsedUrl.hostOf(url);
    }


    /**
     * Validate a JDBC url supplied by a user: it must use the expected driver scheme, carry no
     * driver properties (those can load arbitrary classes / open arbitrary sockets) and its host
     * must not be an internal address.
     *
     * @param jdbcUrl user supplied jdbc url, e.g. jdbc:postgresql://db.example.com:5432/test
     * @param subprotocol expected sub protocol, e.g. postgresql or db2
     * @return true if the url may be used, false otherwise
     */
    public static boolean checkJdbcUrl(String jdbcUrl, String subprotocol) {
        return buildJdbcUrl(jdbcUrl, subprotocol) != null;
    }


    /**
     * Validate a user supplied JDBC url and rebuild it from the validated parts. Only the fixed
     * driver prefixes in {@link #JDBC_SUBPROTOCOLS}, an allowlisted port (or none), a strict host
     * name that resolves to public addresses only and a plain database name are accepted.
     * Driver properties (query, ';', '=') are always rejected. Callers must connect with the
     * returned string only, never with the raw input.
     *
     * @param jdbcUrl user supplied jdbc url, e.g. jdbc:postgresql://db.example.com:5432/test
     * @param subprotocol expected sub protocol, e.g. postgresql or db2
     * @return server-constructed jdbc url, or null if the url must not be used
     */
    public static String buildJdbcUrl(String jdbcUrl, String subprotocol) {
        if (jdbcUrl == null || subprotocol == null || !JDBC_SUBPROTOCOLS.contains(subprotocol)) {
            return null;
        }
        String prefix = "jdbc:" + subprotocol + "://";
        if (!jdbcUrl.startsWith(prefix)) {
            return null;
        }
        String rest = jdbcUrl.substring(prefix.length());
        String authority = rest;
        String database = "";
        int slash = rest.indexOf('/');
        if (slash >= 0) {
            authority = rest.substring(0, slash);
            database = rest.substring(slash + 1);
        }
        if (!database.isEmpty() && !JDBC_DB_NAME_PATTERN.matcher(database).matches()) {
            return null;
        }
        String host = authority;
        int port = -1;
        int colon = authority.lastIndexOf(':');
        if (colon >= 0) {
            host = authority.substring(0, colon);
            String portPart = authority.substring(colon + 1);
            if (!JDBC_PORTS.contains(portPart)) {
                return null;
            }
            port = Integer.parseInt(portPart);
        }
        if (!ParsedUrl.isValidHost(host)) {
            return null;
        }
        host = host.toLowerCase(Locale.ROOT);
        if (!SSRFChecker.isSafeHttpUrl("http://" + host + "/")) {
            return null;
        }
        StringBuilder sb = new StringBuilder(prefix).append(host);
        if (port != -1) {
            sb.append(':').append(port);
        }
        if (!database.isEmpty()) {
            sb.append('/').append(database);
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
            logger.error("Url check failed", e);
            return null;
        }
    }


    /**
     * Validate a user supplied redirect target. It is accepted only if it is either an absolute
     * http(s) url whose host passes {@link #checkURL(String)} (safe domain list), or a same-site
     * absolute path such as <code>/a/b</code>. Protocol-relative urls (<code>//host</code>),
     * backslashes and control characters are rejected.
     *
     * @param url user supplied redirect target
     * @return the original url if it is safe to redirect to, otherwise null
     */
    public static String checkRedirectURL(String url) {
        if (url == null || url.isEmpty()) {
            return null;
        }
        for (int i = 0; i < url.length(); i++) {
            char ch = url.charAt(i);
            if (ch == '\\' || Character.isISOControl(ch) || Character.isWhitespace(ch)) {
                return null;
            }
        }
        if (url.startsWith("/")) {
            // Same-site path only: "//host" and "/\host" are treated as network-path by browsers.
            if (url.startsWith("//")) {
                return null;
            }
            return url;
        }
        return checkURL(url);
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
                logger.info("Unsupported encoding exception");
                return null;
            } catch (Exception e) {
                logger.info("Path decode failed", e);
                return null;
            }
        }

        if (temp.contains("..") || temp.charAt(0) == '/') {
            return null;
        }

        return filepath;
    }


    /**
     * Make an attacker-controlled value safe to use as an HTTP header value (or Location value)
     * by removing CR, LF and all other ISO control characters (horizontal tab is kept),
     * which prevents HTTP response splitting / header injection.
     *
     * @param value untrusted header value, may be null
     * @return the value without control characters, or null if value is null
     */
    public static String sanitizeHeaderValue(String value) {
        if (value == null) {
            return null;
        }
        StringBuilder sb = new StringBuilder(value.length());
        for (int i = 0; i < value.length(); i++) {
            char ch = value.charAt(i);
            if (ch == '\t' || !Character.isISOControl(ch)) {
                sb.append(ch);
            }
        }
        return sb.toString();
    }


    /**
     * Rebuild a value character by character. Every character that is accepted is looked up in the
     * server-owned {@code allowed} table and the table's character is appended, so the result is a
     * new String assembled only from whitelisted constants. Anything else is dropped.
     */
    private static String rebuildFrom(String value, String allowed, int maxLength) {
        if (value == null) {
            return null;
        }
        StringBuilder sb = new StringBuilder(Math.min(value.length(), maxLength));
        for (int i = 0; i < value.length() && sb.length() < maxLength; i++) {
            int idx = allowed.indexOf(value.charAt(i));
            if (idx >= 0) {
                sb.append(allowed.charAt(idx));
            }
        }
        return sb.toString();
    }


    /**
     * Rebuild an untrusted value so that it only consists of characters from the whitelist
     * <code>[A-Za-z0-9 _.,:=@/+-]</code> (at most {@code maxLength} characters). Suitable for
     * header and cookie values.
     *
     * @param value untrusted value, may be null
     * @param maxLength maximum length of the result
     * @return newly assembled value, or null if value is null
     */
    public static String whitelistRebuild(String value, int maxLength) {
        return rebuildFrom(value, HEADER_VALUE_CHARS, maxLength);
    }


    /**
     * Rebuild an untrusted value for use as a cookie value: only <code>[A-Za-z0-9_.:=@/+-]</code>
     * (no space, comma, semicolon, quote or backslash), at most {@code maxLength} characters.
     *
     * @param value untrusted value, may be null
     * @param maxLength maximum length of the result
     * @return newly assembled value, or null if value is null
     */
    public static String cookieValueRebuild(String value, int maxLength) {
        return rebuildFrom(value, COOKIE_VALUE_CHARS, maxLength);
    }


    /**
     * Compare an untrusted value with a server-owned allowlist and return the matching constant
     * from the allowlist (never the untrusted string itself).
     *
     * @param value untrusted value, may be null
     * @param allowlist server-owned constants
     * @return the matching element of the allowlist, or null if nothing matches
     */
    public static String matchAllowlisted(String value, Collection<String> allowlist) {
        if (value == null || allowlist == null) {
            return null;
        }
        for (String candidate : allowlist) {
            if (candidate != null && candidate.equals(value)) {
                return candidate;
            }
        }
        return null;
    }


    /**
     * Validate an Origin / Referer style url against the safe-domain list ({@link #checkURL(String)})
     * and return a server-built origin (<code>scheme://host[:port]</code>) that is assembled from
     * constants (scheme from a fixed list, host characters from a whitelist table, port from an int).
     * The request string itself is never returned.
     *
     * @param origin untrusted Origin header value
     * @return server-built origin, or null if the origin is not allowed
     */
    public static String safeOrigin(String origin) {
        if (checkURL(origin) == null) {
            return null;
        }
        ParsedUrl parsed = ParsedUrl.parse(origin);
        if (parsed == null) {
            return null;
        }
        String scheme = matchAllowlisted(parsed.scheme, SCHEMES);
        String host = rebuildFrom(parsed.host, HOST_CHARS, 253);
        if (scheme == null || host == null || host.isEmpty()) {
            return null;
        }
        StringBuilder sb = new StringBuilder(scheme).append("://").append(host);
        if (parsed.port != -1) {
            sb.append(':').append(parsed.port);
        }
        return sb.toString();
    }


    /**
     * Validate a redirect target ({@link #checkRedirectURL(String)}) and return a server-built
     * Location value: scheme from a fixed list, host / path / query re-assembled from whitelist
     * tables. Targets containing any character outside the whitelist are rejected.
     *
     * @param url untrusted redirect target
     * @return server-built redirect target, or null if the target must not be used
     */
    public static String safeRedirectLocation(String url) {
        String checked = checkRedirectURL(url);
        if (checked == null) {
            return null;
        }
        if (checked.startsWith("/")) {
            String path = rebuildFrom(checked, URL_CHARS, MAX_URL_LENGTH);
            return path.equals(checked) ? path : null;
        }
        ParsedUrl parsed = ParsedUrl.parse(checked);
        if (parsed == null) {
            return null;
        }
        String scheme = matchAllowlisted(parsed.scheme, SCHEMES);
        String host = rebuildFrom(parsed.host, HOST_CHARS, 253);
        String path = rebuildFrom(parsed.path, URL_CHARS, MAX_URL_LENGTH);
        if (scheme == null || host == null || host.isEmpty() || path == null) {
            return null;
        }
        StringBuilder sb = new StringBuilder(scheme).append("://").append(host);
        if (parsed.port != -1) {
            sb.append(':').append(parsed.port);
        }
        sb.append(path);
        if (parsed.query != null) {
            sb.append('?').append(rebuildFrom(parsed.query, URL_CHARS, MAX_URL_LENGTH));
        }
        return sb.toString();
    }


    /**
     * Build a download file name for a Content-Disposition header from untrusted input. The name is
     * re-assembled from <code>[A-Za-z0-9._-]</code> only (max 64 chars); when nothing is left a
     * server-generated UUID is used. The result needs no further escaping (RFC 5987 safe).
     *
     * @param untrustedName untrusted file name, may be null
     * @return server-built file name, never null or empty
     */
    public static String safeFilename(String untrustedName) {
        String name = rebuildFrom(untrustedName, FILENAME_CHARS, 64);
        if (name == null || name.isEmpty() || name.replace(".", "").isEmpty()) {
            return UUID.randomUUID().toString();
        }
        return name;
    }


    public static String cmdFilter(String input) {
        if (input == null || !FILTER_PATTERN.matcher(input).matches()) {
            return null;
        }

        return input;
    }


    /**
     * Parse a user supplied command line into an argv array without involving a shell.
     * The program must be on a fixed allowlist and every argument must match a strict
     * character set, so the result can be passed directly to ProcessBuilder.
     *
     * @param cmd user supplied command line, e.g. "ls -la /tmp"
     * @return argv array, or null if the command is not allowed
     */
    public static String[] cmdArgv(String cmd) {
        if (cmd == null) {
            return null;
        }
        String trimmed = cmd.trim();
        if (trimmed.isEmpty()) {
            return null;
        }
        String[] argv = trimmed.split("\\s+");
        if (!CMD_ALLOWLIST.contains(argv[0])) {
            return null;
        }
        for (int i = 1; i < argv.length; i++) {
            if (!CMD_ARG_PATTERN.matcher(argv[i]).matches()) {
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