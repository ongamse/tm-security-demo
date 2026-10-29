package org.joychou.security;

import org.joychou.config.WebConfig;
import org.joychou.security.ssrf.SSRFChecker;
import org.joychou.security.ssrf.SafeUrl;
import org.joychou.security.ssrf.SocketHook;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.regex.Pattern;


public class SecurityUtil {

    private static final Pattern FILTER_PATTERN = Pattern.compile("^[a-zA-Z0-9_/\\.-]+$");
    private static Logger logger = LoggerFactory.getLogger(SecurityUtil.class);


    private static final int LOG_MAX_LENGTH = 200;

    /**
     * Make a value safe to write to a log line (CWE-117). The result is a freshly constructed
     * string in which CR, LF, TAB and every other control or non-printable character is replaced
     * by '_', and which is capped at {@value #LOG_MAX_LENGTH} characters.
     *
     * @param value untrusted value, may be null
     * @return sanitized copy that is safe to log
     */
    public static String logSafe(Object value) {
        if (value == null) {
            return "null";
        }
        String s = String.valueOf(value);
        int len = Math.min(s.length(), LOG_MAX_LENGTH);
        StringBuilder sb = new StringBuilder(len + 3);
        for (int i = 0; i < len; i++) {
            char c = s.charAt(i);
            if (Character.isISOControl(c) || Character.isSurrogate(c)
                    || Character.isWhitespace(c) && c != ' '
                    || Character.getType(c) == Character.FORMAT
                    || Character.getType(c) == Character.LINE_SEPARATOR
                    || Character.getType(c) == Character.PARAGRAPH_SEPARATOR
                    || Character.getType(c) == Character.UNASSIGNED) {
                sb.append('_');
            } else {
                sb.append(c);
            }
        }
        if (s.length() > LOG_MAX_LENGTH) {
            sb.append("...");
        }
        return sb.toString();
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
            if (url == null) {
                return "";
            }
            SafeUrl parsed = SafeUrl.parseSyntax(url);
            if (parsed == null) {
                return "";
            }
            return parsed.getHost();
        } catch (RuntimeException e) {
            return "";
        }
    }


    /**
     * 同时支持一级域名和多级域名，相关配置在resources目录下url/url_safe_domain.xml文件。
     * 优先判断黑名单，如果满足黑名单return null。
     *
     * @param url the url need to check
     * @return Safe url returns the url rebuilt from its validated components; Illegal url returns null;
     */
    public static String checkURL(String url) {

        if (null == url){
            return null;
        }

        ArrayList<String> safeDomains = WebConfig.getSafeDomains();
        ArrayList<String> blockDomains = WebConfig.getBlockDomains();

        try {
            // Parse once; everything below (and the returned value) uses the parsed components only.
            SafeUrl parsed = SafeUrl.parseSyntax(url);
            if (parsed == null) {
                return null;
            }

            // 必须http/https
            if (!"http".equals(parsed.getScheme()) && !"https".equals(parsed.getScheme())) {
                return null;
            }
            String host = parsed.getHost();
            String safeUrl = parsed.toCanonicalString();

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
                return safeUrl;
            }

            // 支持一级域名
            for(String safedomain: safeDomains) {
                if(host.endsWith("." + safedomain)) {
                    return safeUrl;
                }
            }
            return null;
        } catch (NullPointerException e) {
            logger.error("Safe url check exception: {}", e.getClass().getSimpleName());
            return null;
        }
    }


    /**
     * Build an allowed-character alphabet from character ranges plus a few short extra characters.
     *
     * @param upper  include A-Z
     * @param extras additional literal characters (each argument is a short string)
     * @return the alphabet: a-z, optionally A-Z, 0-9, then the extras
     */
    private static String buildAlphabet(boolean upper, String... extras) {
        StringBuilder sb = new StringBuilder();
        for (char c = 'a'; c <= 'z'; c++) {
            sb.append(c);
        }
        if (upper) {
            for (char c = 'A'; c <= 'Z'; c++) {
                sb.append(c);
            }
        }
        for (char c = '0'; c <= '9'; c++) {
            sb.append(c);
        }
        for (String extra : extras) {
            sb.append(extra);
        }
        return sb.toString();
    }

    private static final String HOST_ALPHABET = buildAlphabet(false, "-");
    private static final String PATH_ALPHABET = buildAlphabet(true, "._~!$&'()*+", ",;=:@%/-");
    private static final String QUERY_ALPHABET = PATH_ALPHABET + "?";
    private static final Pattern HOST_PREFIX_PATTERN = Pattern.compile("[a-z0-9-]+(\\.[a-z0-9-]+)*");
    private static final Pattern BAD_PERCENT_PATTERN = Pattern.compile("%(?![0-9A-Fa-f]{2})");

    /**
     * Rebuild a string character by character from a server side constant alphabet.
     *
     * @return a freshly constructed copy, or null if a character is not in the alphabet
     */
    private static String rebuild(String value, String alphabet) {
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
     * Build a redirect target from a request supplied url without ever using the request string as
     * the target. The request url is only used to select an entry of the server side safe domain
     * allowlist ({@link WebConfig#getSafeDomains()}); the returned url is composed of
     * <ul>
     *   <li>a constant scheme (http or https),</li>
     *   <li>the allowlist's own stored domain string (plus, for a sub domain, a validated
     *       label prefix rebuilt from a constant alphabet),</li>
     *   <li>the port as an integer,</li>
     *   <li>a validated percent-encoded absolute path that starts with a single "/" (never "//"
     *       or "/\"), and a validated query rebuilt from a constant alphabet.</li>
     * </ul>
     *
     * @param url the untrusted url
     * @return the server composed redirect url, or null if the url is not allowed
     */
    public static String safeRedirectUrl(String url) {
        String checked = checkURL(url);
        if (checked == null) {
            return null;
        }
        SafeUrl parsed = SafeUrl.parseSyntax(checked);
        if (parsed == null) {
            return null;
        }

        String scheme;
        if ("https".equals(parsed.getScheme())) {
            scheme = "https";
        } else if ("http".equals(parsed.getScheme())) {
            scheme = "http";
        } else {
            return null;
        }

        // Select the allowlist entry; use the stored string, not the request's.
        String host = parsed.getHost();
        String base = null;
        for (String safeDomain : WebConfig.getSafeDomains()) {
            if (host.equals(safeDomain)) {
                base = safeDomain;
                break;
            }
            if (host.endsWith("." + safeDomain)) {
                String prefix = host.substring(0, host.length() - safeDomain.length() - 1);
                if (!HOST_PREFIX_PATTERN.matcher(prefix).matches()) {
                    return null;
                }
                StringBuilder sb = new StringBuilder();
                for (String label : prefix.split("\\.")) {
                    String safeLabel = rebuild(label, HOST_ALPHABET);
                    if (safeLabel == null || safeLabel.isEmpty()) {
                        return null;
                    }
                    sb.append(safeLabel).append('.');
                }
                base = sb.append(safeDomain).toString();
                break;
            }
        }
        if (base == null) {
            return null;
        }

        StringBuilder target = new StringBuilder(scheme).append("://").append(base);
        if (parsed.getPort() >= 0) {
            target.append(':').append(Integer.toString(parsed.getPort()));
        }

        String path = parsed.getPath();
        if (!path.isEmpty()) {
            if (!path.startsWith("/") || path.startsWith("//") || path.startsWith("/\\")
                    || BAD_PERCENT_PATTERN.matcher(path).find()) {
                return null;
            }
            String safePath = rebuild(path, PATH_ALPHABET);
            if (safePath == null) {
                return null;
            }
            target.append(safePath);
        }

        String query = parsed.getQuery();
        if (query != null) {
            if (BAD_PERCENT_PATTERN.matcher(query).find()) {
                return null;
            }
            String safeQuery = rebuild(query, QUERY_ALPHABET);
            if (safeQuery == null) {
                return null;
            }
            target.append(safeQuery);
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
                logger.info("Unsupported encoding for file path");
                return null;
            } catch (Exception e) {
                logger.info("File path decode exception: {}", e.getClass().getSimpleName());
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

    /**
     * The only characters that may appear in a header value derived from request data. It contains
     * no CR, LF or any other control character, no space, backslash or double quote.
     */
    private static final String HEADER_ALPHABET = buildAlphabet(true, "._~:/?#[]@", "!$&'()*+,;=%-");
    private static final Pattern HEADER_VALUE_PATTERN =
            Pattern.compile("[A-Za-z0-9._~:/?#\\[\\]@!$&'()*+,;=%-]{0,512}");

    /**
     * Turn request derived data into a value that is safe for an HTTP response header
     * (CRLF injection / response splitting).
     *
     * <p>The value must fully match a strict allowlist (at most 512 characters, no CR, LF or any other
     * control character). If it does, the returned string is built character by character from the
     * server side constant {@link #HEADER_ALPHABET}; the request string itself is never returned.
     * Anything else is rejected.</p>
     *
     * @param value untrusted header value, may be null
     * @return a freshly constructed copy of the value, or null if the value is null or not allowed
     */
    public static String safeHeaderValue(String value) {
        if (value == null || !HEADER_VALUE_PATTERN.matcher(value).matches()) {
            return null;
        }
        StringBuilder sb = new StringBuilder(value.length());
        for (int i = 0; i < value.length(); i++) {
            int idx = HEADER_ALPHABET.indexOf(value.charAt(i));
            if (idx < 0) {
                return null;
            }
            sb.append(HEADER_ALPHABET.charAt(idx));
        }
        return sb.toString();
    }

    private static final String COOKIE_ALPHABET = buildAlphabet(true, "_.-");
    private static final int COOKIE_INPUT_MAX_LENGTH = 256;

    /**
     * Turn request derived data into a value that is safe for an HTTP cookie value
     * (CRLF injection / response splitting, cookie attribute injection).
     *
     * <p>The input is capped at 256 characters, encoded as URL-safe Base64 (no padding) and the encoded
     * text is then built character by character from the server side constant {@link #COOKIE_ALPHABET}.
     * The request string itself is never returned, and the result can only contain
     * {@code A-Z a-z 0-9 - _}, so it cannot carry CR, LF, ';', ',' or whitespace. Use
     * {@link #decodeCookieValue(String)} to read the original text back.</p>
     *
     * @param value untrusted cookie value, may be null
     * @return a freshly constructed encoded value, or null if the value is null
     */
    public static String safeCookieValue(String value) {
        if (value == null) {
            return null;
        }
        String capped = value.length() > COOKIE_INPUT_MAX_LENGTH ? value.substring(0, COOKIE_INPUT_MAX_LENGTH) : value;
        String encoded = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(capped.getBytes(StandardCharsets.UTF_8));
        StringBuilder sb = new StringBuilder(encoded.length());
        for (int i = 0; i < encoded.length(); i++) {
            int idx = COOKIE_ALPHABET.indexOf(encoded.charAt(i));
            if (idx >= 0) {
                sb.append(COOKIE_ALPHABET.charAt(idx));
            }
        }
        return sb.toString();
    }

    /**
     * Reverse of {@link #safeCookieValue(String)}.
     * The result is plain, unescaped text: callers must encode it for the output context (e.g. HTML).
     *
     * @param cookieValue a cookie value produced by {@link #safeCookieValue(String)}, may be null
     * @return the original text, or an empty string if the value is null or not valid encoded data
     */
    public static String decodeCookieValue(String cookieValue) {
        if (cookieValue == null || cookieValue.isEmpty()) {
            return "";
        }
        try {
            return new String(Base64.getUrlDecoder().decode(cookieValue), StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            return "";
        }
    }

    /**
     * Exact-match lookup of a request Origin in the fixed server side CORS origin allowlist
     * ({@link WebConfig#getCorsAllowedOrigins()}, full scheme://host[:port] strings).
     * No wildcard / sub domain matching and "null" never matches.
     *
     * @param origin the Origin request header
     * @return the allowlist's OWN stored string for the matching entry (never the request string),
     *         otherwise null
     */
    public static String allowedOrigin(String origin) {
        if (origin == null) {
            return null;
        }
        for (String allowed : WebConfig.getCorsAllowedOrigins()) {
            if (allowed.equals(origin)) {
                return allowed;
            }
        }
        return null;
    }

    public static void main(String[] args) {
    }

}