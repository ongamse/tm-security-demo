package org.joychou.security;

import org.joychou.config.WebConfig;
import org.joychou.security.ssrf.SSRFChecker;
import org.joychou.security.ssrf.SocketHook;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLDecoder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;


public class SecurityUtil {

    private static final Pattern FILTER_PATTERN = Pattern.compile("^[a-zA-Z0-9_/\\.-]+$");
    private static final Pattern HOST_PATTERN = Pattern.compile("^[a-zA-Z0-9][a-zA-Z0-9\\.-]*(:[0-9]{1,5})?$");
    private static final Pattern CONTROL_OR_SPACE_PATTERN = Pattern.compile("[\\p{Cntrl}\\s\\u0085\\u2028\\u2029]");
    private static Logger logger = LoggerFactory.getLogger(SecurityUtil.class);

    /**
     * Exact, scheme-qualified origins that may receive CORS (and credentialed CORS) responses.
     * Shared by Cors, OriginFilter and CustomCorsConfig. The Access-Control-Allow-Origin header must be
     * written from an element of this list, never from the request Origin header value.
     */
    public static final List<String> ALLOWED_CORS_ORIGINS = Collections.unmodifiableList(Arrays.asList(
            "https://joychou.org",
            "https://test.joychou.org",
            "https://joychou.com",
            "https://test.joychou.me",
            "http://test.joychou.me"));

    private static final int MAX_URL_LENGTH = 2048;
    private static final int MAX_HOST_LENGTH = 253;
    private static final String PATH_CHARS = "[A-Za-z0-9._~!$&'()*+,;=:@%/-]*";
    private static final String QUERY_CHARS = "[A-Za-z0-9._~!$&'()*+,;=:@%/?-]*";
    /** Absolute http(s) url: no userinfo, no ipv6 literal, no backslash/whitespace/control/non-ascii characters. */
    private static final Pattern STRICT_HTTP_URL = Pattern.compile(
            "^https?://[A-Za-z0-9.-]{1,253}(:\\d{1,5})?(/" + PATH_CHARS + ")?(\\?" + QUERY_CHARS + ")?$");
    /** Same-origin relative url: a single leading slash, optional query and optional fragment. */
    private static final Pattern STRICT_RELATIVE_URL = Pattern.compile(
            "^/(?!/)" + PATH_CHARS + "(\\?" + QUERY_CHARS + ")?(#" + QUERY_CHARS + ")?$");


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
     * The one central place where an untrusted absolute url string is converted. The string must match a strict
     * character/length pattern first and is only then parsed. The returned URI is a NEW object built from the
     * validated components: scheme (fixed literal http/https), lower-case host, port and the raw path/query.
     *
     * @param url untrusted url
     * @return rebuilt http(s) URI, or null if the url is not acceptable
     */
    public static URI parseHttpUri(String url) {
        if (null == url || url.length() > MAX_URL_LENGTH || !STRICT_HTTP_URL.matcher(url).matches()) {
            return null;
        }
        try {
            URI parsed = new URI(url);
            String host = parsed.getHost();
            int port = parsed.getPort();
            if (null == host || host.isEmpty() || host.length() > MAX_HOST_LENGTH || port > 65535 || port == 0) {
                return null;
            }
            String scheme = "https".equals(parsed.getScheme()) ? "https" : "http";
            return new URI(buildHttpUrl(scheme, host.toLowerCase(Locale.ROOT), port,
                    parsed.getRawPath(), parsed.getRawQuery()));
        } catch (URISyntaxException e) {
            return null;
        }
    }


    private static String buildHttpUrl(String scheme, String host, int port, String rawPath, String rawQuery) {
        StringBuilder sb = new StringBuilder(scheme).append("://").append(host);
        if (port != -1) {
            sb.append(':').append(port);
        }
        if (null != rawPath) {
            sb.append(rawPath);
        }
        if (null != rawQuery) {
            sb.append('?').append(rawQuery);
        }
        return sb.toString();
    }


    /**
     * Validate a same-origin relative url (single leading slash, no authority) and rebuild it from the parsed
     * path/query/fragment.
     *
     * @param url           untrusted relative url
     * @param allowFragment whether a #fragment is accepted
     * @return rebuilt relative url, or null if it is not acceptable
     */
    public static String parseRelativeUrl(String url, boolean allowFragment) {
        if (null == url || url.length() > MAX_URL_LENGTH || !STRICT_RELATIVE_URL.matcher(url).matches()) {
            return null;
        }
        try {
            URI parsed = new URI(url);
            if (parsed.getScheme() != null || parsed.getRawAuthority() != null || parsed.getRawPath() == null
                    || (!allowFragment && parsed.getRawFragment() != null)) {
                return null;
            }
            StringBuilder sb = new StringBuilder(parsed.getRawPath());
            if (parsed.getRawQuery() != null) {
                sb.append('?').append(parsed.getRawQuery());
            }
            if (parsed.getRawFragment() != null) {
                sb.append('#').append(parsed.getRawFragment());
            }
            return sb.toString();
        } catch (URISyntaxException e) {
            return null;
        }
    }


    /**
     * Get http url host.
     *
     * @param url url
     * @return host
     */
    public static String gethost(String url) {
        URI uri = parseHttpUri(url);
        return uri == null ? "" : uri.getHost();
    }


    /**
     * 同时支持一级域名和多级域名，相关配置在resources目录下url/url_safe_domain.xml文件。
     * 优先判断黑名单，如果满足黑名单return null。
     *
     * @param url the url need to check
     * @return Safe url returns the url rebuilt from its validated components; Illegal url returns null;
     */
    public static String checkURL(String url) {

        // 必须http/https，并且通过严格的字符校验；返回的是由校验后的组件重新构造的URI
        URI uri = parseHttpUri(url);
        if (null == uri) {
            return null;
        }

        ArrayList<String> safeDomains = WebConfig.getSafeDomains();
        ArrayList<String> blockDomains = WebConfig.getBlockDomains();

        try {
            String host = uri.getHost();

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
                return uri.toString();
            }

            // 支持一级域名
            for(String safedomain: safeDomains) {
                if(host.endsWith("." + safedomain)) {
                    return uri.toString();
                }
            }
            return null;
        } catch (NullPointerException e) {
            logger.error("Check url failed: {}", e.getClass().getSimpleName());
            return null;
        }
    }


    /**
     * Validate a request Origin header value before it is echoed in Access-Control-Allow-Origin.
     * The value must be a bare http(s) origin (scheme://host[:port], no userinfo/path/query/fragment,
     * no whitespace/control/backslash characters) whose host passes {@link #checkURL(String)}.
     * The literal <code>null</code> origin and <code>*</code> are never accepted.
     *
     * @param origin the Origin header value
     * @return the origin if it is trusted, otherwise null
     */
    public static String safeCorsOrigin(String origin) {
        if (null == origin || origin.isEmpty() || hasRedirectUnsafeChars(origin)) {
            return null;
        }
        URI uri = parseHttpUri(origin);
        if (uri == null) {
            return null;
        }
        String path = uri.getRawPath();
        if (uri.getHost() == null || uri.getRawUserInfo() != null
                || (path != null && !path.isEmpty())
                || uri.getRawQuery() != null || uri.getRawFragment() != null) {
            return null;
        }
        return checkURL(uri.toString());
    }


    /**
     * Match the request Origin against {@link #ALLOWED_CORS_ORIGINS} and return the matching allowlist element
     * (the static constant, not the request value), so the Access-Control-Allow-Origin header is never derived
     * from request data. Exact string comparison only; the literal <code>null</code> origin never matches.
     *
     * @param origin the request Origin header value
     * @return the allowlisted origin that equals the request origin, otherwise null
     */
    public static String matchAllowedCorsOrigin(String origin) {
        if (null == origin) {
            return null;
        }
        for (String allowed : ALLOWED_CORS_ORIGINS) {
            if (allowed.equals(origin)) {
                return allowed;
            }
        }
        return null;
    }


    /**
     * Backslashes, whitespace and control characters are normalized or dropped by browsers and by
     * {@link java.net.URL}, so they can be used to disguise an off-site redirect target.
     *
     * @param url url to inspect
     * @return true if the url contains such a character
     */
    public static boolean hasRedirectUnsafeChars(String url) {
        return url.indexOf('\\') != -1 || CONTROL_OR_SPACE_PATTERN.matcher(url).find();
    }


    /**
     * Validate a user supplied redirect target. Only two kinds of targets are accepted:
     * <ul>
     *   <li>a same-origin relative path starting with a single <code>/</code> (no <code>//host</code>,
     *   no backslash, no control characters, no scheme/authority);</li>
     *   <li>an absolute http(s) url whose host passes {@link #checkURL(String)} (domain allowlist).</li>
     * </ul>
     *
     * @param url the redirect target supplied by the user
     * @return the url if it is a safe redirect target, otherwise null
     */
    public static String safeRedirectUrl(String url) {
        if (null == url || url.isEmpty()) {
            return null;
        }

        // Browsers normalize backslash to slash and ignore tab/CR/LF, which turns
        // "/\evil.com" or "/\t/evil.com" into a protocol-relative url.
        if (hasRedirectUnsafeChars(url)) {
            return null;
        }

        if (url.startsWith("/")) {
            // strict character check, then rebuilt from the parsed path/query/fragment
            return parseRelativeUrl(url, true);
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
                logger.info("Unsupported encoding exception.");
                return null;
            } catch (Exception e) {
                logger.info("Illegal encoding in file path: {}", e.getClass().getSimpleName());
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
     * Map a user supplied command key to a fixed argv array for shell-free execution.
     * The request value is only used as a lookup key; the returned argv consists solely of
     * literal constants, so no request-derived string ever reaches Runtime.exec / ProcessBuilder.
     *
     * @param cmd user supplied command key
     * @return literal argv for Runtime.exec(String[]) / ProcessBuilder, or null if the key is not allowed
     */
    public static String[] parseAllowedCommand(String cmd) {
        if (null == cmd) {
            return null;
        }

        switch (cmd.trim().replaceAll("\\s+", " ")) {
            case "whoami":
                return new String[]{"whoami"};
            case "id":
                return new String[]{"id"};
            case "uname":
                return new String[]{"uname"};
            case "uname -a":
                return new String[]{"uname", "-a"};
            case "pwd":
                return new String[]{"pwd"};
            case "ls":
                return new String[]{"ls"};
            case "ls -la":
                return new String[]{"ls", "-la"};
            default:
                return null;
        }
    }


    /**
     * Map a user supplied directory key to a fixed directory literal that may be listed.
     *
     * @param filepath user supplied directory key
     * @return literal directory path, or null if the key is not allowed
     */
    public static String resolveAllowedDir(String filepath) {
        if (null == filepath) {
            return null;
        }

        switch (filepath) {
            case "/tmp":
                return "/tmp";
            case "/var/tmp":
                return "/var/tmp";
            case "/usr/share":
                return "/usr/share";
            default:
                return null;
        }
    }


    /**
     * Map a Host header value to a fixed host literal that may be requested.
     *
     * @param host Host header value
     * @return literal host, or null if the host is not allowed
     */
    public static String resolveAllowedHost(String host) {
        if (null == host) {
            return null;
        }

        switch (host) {
            case "localhost":
                return "localhost";
            case "localhost:8080":
                return "localhost:8080";
            case "127.0.0.1":
                return "127.0.0.1";
            case "127.0.0.1:8080":
                return "127.0.0.1:8080";
            default:
                return null;
        }
    }


    /**
     * Validate the Host header value before it is used as a command argument.
     * Only a hostname with an optional port is accepted.
     *
     * @param host host header value
     * @return the host if valid, otherwise null
     */
    public static String hostFilter(String host) {
        if (null == host || !HOST_PATTERN.matcher(host).matches()) {
            return null;
        }
        return host;
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