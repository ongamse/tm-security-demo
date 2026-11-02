package org.joychou.security;

import org.joychou.config.WebConfig;
import org.joychou.security.ssrf.SSRFChecker;
import org.joychou.security.ssrf.SocketHook;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
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
        // strict component parser: no URI/URL object is built from the raw request data
        SafeUrl parsed = SafeUrl.parse(url);
        if (parsed == null) {
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
            logger.error("safeUrl check failed: " + e.getClass().getSimpleName());
            return null;
        }
    }


    /**
     * Closed set of trusted CORS origins (hosts mirror url/url_safe_domain.xml). Key: the exact
     * Origin request header value; value: the constant that may be emitted as
     * Access-Control-Allow-Origin. The literal "null" origin and a missing origin are never trusted.
     */
    public static final Map<String, String> TRUSTED_CORS_ORIGINS;

    static {
        Map<String, String> m = new HashMap<>();
        m.put("https://joychou.com", "https://joychou.com");
        m.put("https://joychou.org", "https://joychou.org");
        m.put("https://test.joychou.org", "https://test.joychou.org");
        m.put("http://localhost", "http://localhost");
        m.put("http://localhost:8080", "http://localhost:8080");
        TRUSTED_CORS_ORIGINS = Collections.unmodifiableMap(m);
    }

    /**
     * Closed set of trusted outbound destinations (hosts mirror url/ssrf_safe_domain.xml). Key: the exact
     * normalised host of an allowed destination; value: the complete constant url that is requested.
     * Nothing from the request (path, query, ...) is ever appended to a value.
     */
    public static final Map<String, String> TRUSTED_OUTBOUND_URLS;

    static {
        Map<String, String> m = new HashMap<>();
        m.put("img.alicdn.com", "https://img.alicdn.com/");
        m.put("www.example.com", "https://www.example.com/");
        TRUSTED_OUTBOUND_URLS = Collections.unmodifiableMap(m);
    }

    /**
     * Select a trusted outbound url for an untrusted url. The request text is only used to look up an
     * entry of {@link #TRUSTED_OUTBOUND_URLS} (after the http/https, port and public host validation of
     * {@link SSRFChecker#validate(String)}); the returned string is always one of the map's constants.
     *
     * @param url untrusted url
     * @return the constant outbound url, or null (fail closed)
     */
    public static String trustedOutboundUrl(String url) {
        SafeUrl parsed = SSRFChecker.validate(url);
        if (parsed == null) {
            return null;
        }
        return TRUSTED_OUTBOUND_URLS.get(parsed.getHost());
    }

    /** Explicit CORS policy constants (no wildcards). */
    public static final String CORS_ALLOW_METHODS = "GET, POST, OPTIONS";
    public static final String CORS_ALLOW_HEADERS = "Content-Type, Authorization";
    public static final String CORS_MAX_AGE = "3600";

    /**
     * Look up an untrusted CORS Origin header value in {@link #TRUSTED_CORS_ORIGINS}.
     *
     * @param origin untrusted value of the Origin request header
     * @return the trusted constant origin from the allowlist, otherwise null
     */
    public static String checkCorsOrigin(String origin) {
        if (origin == null) {
            return null;
        }
        // closed set: the returned value is the map's own constant, never the request text
        return TRUSTED_CORS_ORIGINS.get(origin);
    }


    /**
     * Validate an untrusted redirect target against the configured safe/block domain lists
     * (url/url_safe_domain.xml). See {@link #checkRedirectURL(String, Collection)}.
     *
     * @param url untrusted redirect target
     * @return the original url when safe, otherwise null
     */
    public static String checkRedirectURL(String url) {
        // Absolute URLs must also pass the block-list in checkURL; same-site paths have no host.
        if (url != null && !url.startsWith("/") && checkURL(url) == null) {
            return null;
        }
        return checkRedirectURL(url, WebConfig.getSafeDomains());
    }


    /**
     * Strictly validate an untrusted redirect target.
     * Allowed: a same-site absolute path (single leading slash), or an http/https URL whose
     * host (parsed by java.net.URI) equals an allowed domain or is a sub-domain of it (leading dot match).
     * Rejected: backslashes, whitespace/control characters, userinfo, protocol-relative (//) tricks,
     * other schemes and unparsable URLs.
     *
     * @param url            untrusted redirect target
     * @param allowedDomains allowed domains
     * @return the original url when safe, otherwise null
     */
    public static String checkRedirectURL(String url, Collection<String> allowedDomains) {
        if (url == null || url.isEmpty() || allowedDomains == null) {
            return null;
        }

        for (int i = 0; i < url.length(); i++) {
            char c = url.charAt(i);
            if (c == '\\' || c <= 0x20 || c == 0x7f || Character.isISOControl(c) || Character.isWhitespace(c)) {
                return null;
            }
        }

        // Same-site path: "/a/b" is fine, "//evil.com" is not.
        if (url.charAt(0) == '/') {
            return (url.length() == 1 || url.charAt(1) != '/') ? url : null;
        }

        if (!isHttp(url)) {
            return null;
        }

        SafeUrl parsed = SafeUrl.parse(url);
        if (parsed == null || !parsed.isHttp() || parsed.getUserInfo() != null) {
            return null;
        }
        String host = parsed.getHost();
        for (String domain : allowedDomains) {
            String d = domain.toLowerCase();
            if (host.equals(d) || host.endsWith("." + d)) {
                return url;
            }
        }
        return null;
    }


    /**
     * Validate and URI-encode a same-site relative path (optionally with query) for use in a redirect target.
     * The path must start with a single '/', must not start with "//" or "/\", and must not contain
     * backslashes or control characters (CR/LF included). Existing valid percent-escapes are kept; every
     * other character outside the RFC 3986 path/query set is percent-encoded as UTF-8.
     *
     * @param path untrusted relative path
     * @return the encoded path, or null when the path is not an acceptable same-site path
     */
    public static String safeRelativePath(String path) {
        if (path == null || path.isEmpty() || path.length() > 2048 || path.charAt(0) != '/') {
            return null;
        }
        if (path.length() > 1 && (path.charAt(1) == '/' || path.charAt(1) == '\\')) {
            return null;
        }
        StringBuilder sb = new StringBuilder(path.length() + 16);
        for (int i = 0; i < path.length(); i++) {
            char c = path.charAt(i);
            if (c == '\\' || c <= 0x1f || c == 0x7f || Character.isISOControl(c)) {
                return null;
            }
            boolean plain = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
                    || "-._~/!$&'()*+,;=:@?".indexOf(c) >= 0;
            if (plain) {
                sb.append(c);
            } else if (c == '%' && i + 2 < path.length() &&isHexDigit(path.charAt(i + 1))
                    && isHexDigit(path.charAt(i + 2))) {
                sb.append(c);
            } else {
                int cp = path.codePointAt(i);
                byte[] bytes = new String(Character.toChars(cp)).getBytes(java.nio.charset.StandardCharsets.UTF_8);
                for (byte b : bytes) {
                    sb.append('%').append(String.format("%02X", b & 0xff));
                }
                i += Character.charCount(cp) - 1;
            }
        }
        return sb.toString();
    }

    private static boolean isHexDigit(char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
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
                logger.info("pathFilter decode failed: " + e.getClass().getSimpleName());
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