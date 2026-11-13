package org.joychou.security;

import org.joychou.config.WebConfig;
import org.joychou.security.ssrf.SSRFChecker;
import org.joychou.security.ssrf.SocketHook;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.URL;
import java.net.URLDecoder;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


public class SecurityUtil {

    private static final Pattern FILTER_PATTERN = Pattern.compile("^[a-zA-Z0-9_/\\.-]+$");
    private static final Pattern SHORT_FLAG_PATTERN = Pattern.compile("^-[a-zA-Z]+$");
    private static final Set<String> CMD_ALLOWLIST = new HashSet<String>(
            Arrays.asList("whoami", "pwd", "ls", "id", "uname", "date"));
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
        ParsedUrl parsed = parseHttpUri(url);
        if (parsed == null) {
            return "";
        }
        return parsed.host;
    }


    private static final String PCT = "%[0-9A-Fa-f]{2}";
    // Possessive loops: iterative matching, no deep recursion / backtracking on long untrusted input.
    private static final String PATH_CHARS = "(?:[A-Za-z0-9._~!$&'()*+,;=:@/-]|" + PCT + ")*+";
    private static final String QUERY_CHARS = "(?:[A-Za-z0-9._~!$&'()*+,;=:@/?-]|" + PCT + ")*+";
    private static final Pattern HTTP_URL_PATTERN = Pattern.compile(
            "^((?i:https?))://([A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?)(?::([0-9]{1,5}))?"
                    + "(/" + PATH_CHARS + ")?(?:\\?(" + QUERY_CHARS + "))?(?:#(" + QUERY_CHARS + "))?$");
    private static final Pattern RELATIVE_URL_PATTERN = Pattern.compile(
            "^(/" + PATH_CHARS + ")(?:\\?(" + QUERY_CHARS + "))?(?:#(" + QUERY_CHARS + "))?$");

    private static final String HOST_ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789.-";
    private static final String PATH_ALPHABET =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._~!$&'()*+,;=:@%/-";
    private static final String QUERY_ALPHABET = PATH_ALPHABET + "?";

    /** Characters a URL-encoded (application/x-www-form-urlencoded) header value can consist of. */
    public static final String HEADER_VALUE_ALPHABET =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._~%+*-";
    /** Characters allowed in a download file name. */
    public static final String FILE_NAME_ALPHABET =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-";
    /** Characters of a redirect url produced by {@link #safeRedirectTarget(String)}. */
    public static final String REDIRECT_URL_ALPHABET = QUERY_ALPHABET + "#";


    /**
     * The components of an untrusted absolute http/https url that matched {@link #HTTP_URL_PATTERN}.
     */
    private static final class ParsedUrl {
        final String scheme;
        final String host;
        final int port;
        final String rawPath;
        final String rawQuery;
        final String rawFragment;

        ParsedUrl(String scheme, String host, int port, String rawPath, String rawQuery, String rawFragment) {
            this.scheme = scheme;
            this.host = host;
            this.port = port;
            this.rawPath = rawPath;
            this.rawQuery = rawQuery;
            this.rawFragment = rawFragment;
        }
    }


    /**
     * Parse an untrusted url once with a strict pattern. Only absolute http/https urls without userinfo and
     * with a non-empty host are accepted; scheme and host are returned in lower case.
     *
     * @param raw untrusted url
     * @return the parsed components; null (fail closed) for anything else
     */
    private static ParsedUrl parseHttpUri(String raw) {
        if (raw == null) {
            return null;
        }
        Matcher m = HTTP_URL_PATTERN.matcher(raw);
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
        return new ParsedUrl(m.group(1).toLowerCase(), m.group(2).toLowerCase(), port, m.group(4), m.group(5),
                m.group(6));
    }


    /**
     * Rebuild a value character by character from a closed alphabet: every output character is taken from
     * the (server-owned) alphabet constant, never from the input.
     *
     * @param value    untrusted value
     * @param alphabet the allowed characters
     * @return the rebuilt value; null if the value is null or has a character outside the alphabet
     */
    public static String rebuildFrom(String value, String alphabet) {
        if (value == null) {
            return null;
        }
        StringBuilder sb = new StringBuilder(value.length());
        for (int i = 0; i < value.length(); i++) {
            int idx = alphabet.indexOf(value.charAt(i));
            if (idx < 0) {
                return null;
            }
            sb.append(alphabet.charAt(idx));
        }
        return sb.toString();
    }


    /**
     * Look up the configured allowlist entry (safe domain lists) that equals the host or is a parent domain
     * of it. The returned string is owned by the configuration, not by the request.
     */
    private static String findAllowlistEntry(String host) {
        String parent = null;
        List<List<String>> lists = new ArrayList<List<String>>();
        lists.add(WebConfig.getSafeDomains());
        lists.add(WebConfig.getSsrfSafeDomains());
        for (List<String> domains : lists) {
            if (domains == null) {
                continue;
            }
            for (String domain : domains) {
                if (host.equals(domain)) {
                    return domain;
                }
                if (parent == null && host.endsWith("." + domain)) {
                    parent = domain;
                }
            }
        }
        return parent;
    }


    private static boolean hostOnList(String host, List<String> domains) {
        if (domains == null) {
            return false;
        }
        for (String domain : domains) {
            if (host.equals(domain) || host.endsWith("." + domain)) {
                return true;
            }
        }
        return false;
    }


    private static boolean isInternalAddress(InetAddress address) {
        if (address.isAnyLocalAddress() || address.isLoopbackAddress() || address.isLinkLocalAddress()
                || address.isSiteLocalAddress() || address.isMulticastAddress()) {
            return true;
        }
        if (address instanceof Inet6Address && (address.getAddress()[0] & 0xfe) == 0xfc) {
            return true; // unique local fc00::/7
        }
        if (address instanceof Inet4Address) {
            try {
                return SSRFChecker.isInternalIp(address.getHostAddress());
            } catch (RuntimeException e) {
                return true; // fail closed
            }
        }
        return false;
    }


    /**
     * The single chokepoint for every outbound request to an untrusted url (CWE-918). It is an allowlist
     * lookup that returns a server-owned value:
     * <ol>
     *   <li>the url is matched once against a strict pattern (no userinfo, no backslash, non-empty host);</li>
     *   <li>only https is accepted (plain http is rejected) and the port must be the default, 443 or 8443;</li>
     *   <li>the host must not be blocked and must equal / be a sub domain of a configured safe domain
     *       (decided BEFORE any DNS lookup);</li>
     *   <li>the outgoing host is built from the configured allowlist string (plus the sub domain prefix
     *       rebuilt from the host alphabet), the scheme and port are fixed constants, the path and query
     *       are rebuilt from the closed url alphabets and ".." segments are rejected;</li>
     *   <li>only that host is resolved and every address must be public.</li>
     * </ol>
     * Callers must obtain their url/host only from the returned object and must not follow redirects.
     *
     * @param raw untrusted url
     * @return the validated url
     * @throws IOException if the url must not be requested
     */
    public static URL requireSafeUrl(String raw) throws IOException {
        ParsedUrl parsed = parseHttpUri(raw);
        if (parsed == null || !"https".equals(parsed.scheme)) {
            throw new IOException("[-] SSRF check failed");
        }

        // Fixed port set: the port written into the outgoing url is a constant, never the request's digits.
        int port;
        if (parsed.port == -1 || parsed.port == 443) {
            port = 443;
        } else if (parsed.port == 8443) {
            port = 8443;
        } else {
            throw new IOException("[-] SSRF check failed");
        }

        // Textual allowlist decision before any DNS lookup.
        if (hostOnList(parsed.host, WebConfig.getBlockDomains())
                || hostOnList(parsed.host, WebConfig.getSsrfBlockDomainsDomains())) {
            throw new IOException("[-] SSRF check failed");
        }
        String entry = findAllowlistEntry(parsed.host);
        if (entry == null) {
            throw new IOException("[-] SSRF check failed");
        }
        // Allowlist-owned host: the configured entry, plus the (alphabet rebuilt) sub domain prefix if any.
        String safeHost = entry;
        if (!parsed.host.equals(entry)) {
            String prefix = rebuildFrom(parsed.host.substring(0, parsed.host.length() - entry.length() - 1),
                    HOST_ALPHABET);
            if (prefix == null || prefix.isEmpty()) {
                throw new IOException("[-] SSRF check failed");
            }
            safeHost = prefix + "." + entry;
        }

        // Path (percent-normalized check for dot segments) and query rebuilt from the closed alphabets.
        String rawPath = parsed.rawPath == null || parsed.rawPath.isEmpty() ? "/" : parsed.rawPath;
        String normalized = rawPath.replaceAll("(?i)%2e", ".");
        if (normalized.matches("(?i).*%(2f|5c|00).*")) {
            throw new IOException("[-] SSRF check failed");
        }
        for (String segment : normalized.split("/", -1)) {
            if ("..".equals(segment)) {
                throw new IOException("[-] SSRF check failed");
            }
        }
        String safePath = rebuildFrom(rawPath, PATH_ALPHABET);
        if (safePath == null) {
            throw new IOException("[-] SSRF check failed");
        }
        StringBuilder file = new StringBuilder(safePath);
        if (parsed.rawQuery != null) {
            String safeQuery = rebuildFrom(parsed.rawQuery, QUERY_ALPHABET);
            if (safeQuery == null) {
                throw new IOException("[-] SSRF check failed");
            }
            file.append('?').append(safeQuery);
        }

        InetAddress[] addresses;
        try {
            addresses = InetAddress.getAllByName(safeHost);
        } catch (UnknownHostException e) {
            throw new IOException("[-] SSRF check failed");
        }
        if (addresses == null || addresses.length == 0) {
            throw new IOException("[-] SSRF check failed");
        }
        for (InetAddress address : addresses) {
            if (isInternalAddress(address)) {
                throw new IOException("[-] SSRF check failed");
            }
        }

        return new URL("https", safeHost, port, file.toString());
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
     * Validate and normalize an untrusted redirect target (CWE-601).
     * <p>
     * Accepted: a same-site relative path starting with a single "/" (no scheme, no authority), or an
     * absolute http(s) url without userinfo whose host passes {@link #checkURL(String)}.
     * Rejected: null/blank, whitespace, control characters, backslashes and anything starting with "//".
     * The returned value is rebuilt from the parsed components, never the raw input.
     *
     * @param raw untrusted redirect target
     * @return the validated target to redirect to; null if it must not be redirected to
     */
    public static String safeRedirectTarget(String raw) {
        if (raw == null || raw.trim().isEmpty() || raw.indexOf('\\') != -1 || raw.startsWith("//")) {
            return null;
        }
        for (int i = 0; i < raw.length(); i++) {
            char ch = raw.charAt(i);
            if (Character.isISOControl(ch) || Character.isWhitespace(ch)) {
                return null;
            }
        }

        StringBuilder target = new StringBuilder();
        String path;
        String query;
        String fragment;
        if (raw.startsWith("/")) {
            // Same-site relative path only.
            Matcher rel = RELATIVE_URL_PATTERN.matcher(raw);
            if (!rel.matches()) {
                return null;
            }
            path = rel.group(1);
            query = rel.group(2);
            fragment = rel.group(3);
        } else {
            ParsedUrl parsed = parseHttpUri(raw);
            if (parsed == null || checkURL(raw) == null) {
                return null;
            }
            String host = rebuildFrom(parsed.host, HOST_ALPHABET);
            if (host == null) {
                return null;
            }
            target.append("https".equals(parsed.scheme) ? "https" : "http").append("://").append(host);
            if (parsed.port != -1) {
                target.append(':').append(parsed.port);
            }
            path = parsed.rawPath;
            query = parsed.rawQuery;
            fragment = parsed.rawFragment;
        }

        if (path != null) {
            String safePath = rebuildFrom(path, PATH_ALPHABET);
            if (safePath == null) {
                return null;
            }
            target.append(safePath);
        }
        if (target.length() == 0 || (target.charAt(0) == '/' && (target.length() > 1 && target.charAt(1) == '/'))) {
            return null;
        }
        if (query != null) {
            String safeQuery = rebuildFrom(query, QUERY_ALPHABET);
            if (safeQuery == null) {
                return null;
            }
            target.append('?').append(safeQuery);
        }
        if (fragment != null) {
            String safeFragment = rebuildFrom(fragment, QUERY_ALPHABET);
            if (safeFragment == null) {
                return null;
            }
            target.append('#').append(safeFragment);
        }
        return target.toString();
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
     * Build a shell-free argv from a user supplied command line. Only allowlisted commands
     * are accepted; every argument must match {@link #FILTER_PATTERN} and must not look like an
     * option (except short flags for <code>ls</code>).
     *
     * @param cmd user supplied command line, e.g. <code>ls -la /tmp</code>
     * @return argv for ProcessBuilder / Runtime.exec(String[]); null if the command is not allowed
     */
    public static String[] cmdArgv(String cmd) {
        if (cmd == null) {
            return null;
        }
        String[] tokens = cmd.trim().split("\\s+");
        if (tokens.length == 0 || !CMD_ALLOWLIST.contains(tokens[0])) {
            return null;
        }
        // Only ls and id take arguments; e.g. "date MMDDhhmm" would otherwise set the system clock.
        if (tokens.length > 1 && !"ls".equals(tokens[0]) && !"id".equals(tokens[0])) {
            return null;
        }
        for (int i = 1; i < tokens.length; i++) {
            boolean lsFlag = "ls".equals(tokens[0]) && SHORT_FLAG_PATTERN.matcher(tokens[i]).matches();
            if (!lsFlag && (tokens[i].startsWith("-") || cmdFilter(tokens[i]) == null)) {
                return null;
            }
        }
        return tokens;
    }


    /**
     * Turn an untrusted value into a header / cookie value that is composed only of characters of
     * {@link #HEADER_VALUE_ALPHABET}: the value is percent-encoded (CR / LF become %0D / %0A) and then
     * rebuilt from the server-owned alphabet constant.
     *
     * @param value untrusted value
     * @return the encoded value; "" if the input is null
     */
    public static String encodeHeaderValue(String value) {
        if (value == null) {
            return "";
        }
        String encoded;
        try {
            encoded = java.net.URLEncoder.encode(value, "UTF-8");
        } catch (java.io.UnsupportedEncodingException e) {
            return "";
        }
        String rebuilt = rebuildFrom(encoded, HEADER_VALUE_ALPHABET);
        return rebuilt == null ? "" : rebuilt;
    }


    /**
     * Build a download file name only from {@link #FILE_NAME_ALPHABET}: characters outside the alphabet are
     * replaced by the constant '_'.
     *
     * @param name untrusted file name
     * @return the rebuilt file name; "download" if the input is null or empty
     */
    public static String safeFileName(String name) {
        if (name == null || name.isEmpty()) {
            return "download";
        }
        StringBuilder sb = new StringBuilder(name.length());
        for (int i = 0; i < name.length(); i++) {
            String c = rebuildFrom(String.valueOf(name.charAt(i)), FILE_NAME_ALPHABET);
            sb.append(c == null ? "_" : c);
        }
        return sb.toString();
    }


    /**
     * Strict sanitizer for a value that is written into an HTTP response header, to prevent header
     * injection / response splitting (CWE-113). Removes all ASCII control characters (0x00-0x1F, 0x7F)
     * and the Unicode line separators U+0085, U+2028 and U+2029. Percent-escapes are left as is
     * (the value is never decoded), so an encoded "%0d%0a" stays inert text.
     *
     * @param value untrusted header value
     * @return the value without control / line separator characters; "" if the input is null
     */
    public static String headerFilter(String value) {
        if (value == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder(value.length());
        for (int i = 0; i < value.length(); i++) {
            char ch = value.charAt(i);
            boolean forbidden = ch <= 0x1F || ch == 0x7F
                    || ch == 0x85 || ch == 0x2028 || ch == 0x2029;
            if (!forbidden) {
                sb.append(ch);
            }
        }
        return sb.toString();
    }


    /**
     * Look up the allowlist entry that exactly matches the host of a request Origin and return an
     * Origin value built from the allowlist's own host string (never the request's string).
     * Only http/https origins without userinfo/path/query/fragment whose host exactly equals a
     * configured safe domain (and is not blocked, see {@link #checkURL(String)}) are accepted.
     *
     * @param origin the request Origin header
     * @return the allowlist-owned Origin to echo; null if the origin is not allowed
     */
    public static String allowedOrigin(String origin) {
        if (origin == null || checkURL(origin) == null) {
            return null;
        }
        ParsedUrl parsed = parseHttpUri(origin);
        if (parsed == null) {
            return null;
        }
        String path = parsed.rawPath;
        if (parsed.rawQuery != null || parsed.rawFragment != null || (path != null && !path.isEmpty())) {
            return null;
        }
        String scheme;
        if ("http".equals(parsed.scheme)) {
            scheme = "http";
        } else if ("https".equals(parsed.scheme)) {
            scheme = "https";
        } else {
            return null;
        }
        String host = parsed.host;
        for (String safeDomain : WebConfig.getSafeDomains()) {
            if (safeDomain.equals(host)) {
                StringBuilder allowed = new StringBuilder(scheme).append("://").append(safeDomain);
                if (parsed.port != -1) {
                    allowed.append(':').append(parsed.port);
                }
                return headerFilter(allowed.toString());
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
     * Make an untrusted value safe to write to a log line (CWE-117): replaces CR, LF, other
     * control characters and Unicode line separators with '_' and bounds the length.
     *
     * @param value untrusted value, may be null
     * @return sanitized, truncated value ("null" for null)
     */
    public static String logSafe(String value) {
        final int maxLen = 200;
        if (value == null) {
            return "null";
        }
        boolean truncated = value.length() > maxLen;
        String s = truncated ? value.substring(0, maxLen) : value;
        // CR, LF, NEL, LS, PS and all other control characters (same set as before) become '_'.
        String cleaned = s.replaceAll("[\\r\\n\\u0085\\u2028\\u2029\\p{Cntrl}]", "_");
        return truncated ? cleaned + "..." : cleaned;
    }

    public static void main(String[] args) {
    }

}