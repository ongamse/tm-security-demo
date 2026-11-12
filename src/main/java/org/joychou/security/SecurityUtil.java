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
        if(url == null) {
            return false;
        }
        return !SSRFChecker.isInternalIpByUrl(url);
    }

    /**
     * Strict check for a user supplied URL that the server is about to request.
     * The URL must be an absolute http/https URI without user info, and every address
     * the host resolves to must be a public one (see {@link #isPublicHost(String)}).
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
            if (uri.getRawUserInfo() != null) {
                return false;
            }
            return isPublicHost(uri.getHost());
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
        if (host == null || host.isEmpty()) {
            return false;
        }
        try {
            InetAddress[] addresses = InetAddress.getAllByName(host);
            if (addresses.length == 0) {
                return false;
            }
            for (InetAddress address : addresses) {
                if (address.isAnyLocalAddress() || address.isLoopbackAddress()
                        || address.isLinkLocalAddress() || address.isSiteLocalAddress()
                        || address.isMulticastAddress()) {
                    return false;
                }
                byte[] raw = address.getAddress();
                if (address instanceof Inet4Address) {
                    int first = raw[0] & 0xFF;
                    int second = raw[1] & 0xFF;
                    // 0.0.0.0/8 and carrier-grade NAT 100.64.0.0/10
                    if (first == 0 || (first == 100 && second >= 64 && second <= 127)) {
                        return false;
                    }
                    if (SSRFChecker.isInternalIp(address.getHostAddress())) {
                        return false;
                    }
                } else if ((raw[0] & 0xFE) == 0xFC) {
                    // IPv6 unique local address fc00::/7
                    return false;
                }
            }
            return true;
        } catch (Exception e) {
            logger.error(e.toString());
            return false;
        }
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


    private static final java.util.Set<String> ALLOWED_COMMANDS = new java.util.HashSet<String>(
            java.util.Arrays.asList("whoami", "id", "date", "uname", "hostname", "pwd", "ls"));

    private static final Pattern CMD_ARG_PATTERN = Pattern.compile("^[a-zA-Z0-9_.-]+$");

    /**
     * Parse a user supplied command line into an argv list without involving a shell.
     * Only allowlisted program names and simple arguments (no path separators,
     * no shell metacharacters) are accepted.
     *
     * @param cmd command line, whitespace separated
     * @return argv list that can be passed to ProcessBuilder, or null if not allowed
     */
    public static java.util.List<String> parseAllowedCommand(String cmd) {
        if (cmd == null || cmd.trim().isEmpty()) {
            return null;
        }
        String[] parts = cmd.trim().split("\\s+");
        if (!ALLOWED_COMMANDS.contains(parts[0])) {
            return null;
        }
        java.util.List<String> argv = new ArrayList<String>();
        argv.add(parts[0]);
        for (int i = 1; i < parts.length; i++) {
            if (!CMD_ARG_PATTERN.matcher(parts[i]).matches()) {
                return null;
            }
            argv.add(parts[i]);
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
        StringBuilder sb = new StringBuilder(value.length());
        for (int i = 0; i < value.length(); i++) {
            char ch = value.charAt(i);
            if (!Character.isISOControl(ch)) {
                sb.append(ch);
            }
        }
        return sb.toString();
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
        try {
            URI uri = new URI(origin);
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
        return checkURL(origin);
    }

    /**
     * Validate a user supplied redirect target.
     * Allowed: a same-origin absolute path (single leading slash), or an http(s) url whose host
     * passes {@link #checkURL(String)} (safe/block domain config). Control characters, whitespace,
     * backslashes, protocol-relative urls ("//host") and userinfo ("user@host") are rejected.
     *
     * @param url the redirect target from the request, may be null
     * @return the original url when it is safe to redirect to, otherwise null
     */
    public static String getSafeRedirectUrl(String url) {
        if (url == null || url.isEmpty()) {
            return null;
        }
        for (int i = 0; i < url.length(); i++) {
            char ch = url.charAt(i);
            if (ch == '\\' || Character.isISOControl(ch) || Character.isWhitespace(ch)) {
                return null;
            }
        }

        try {
            URI uri = new URI(url);
            if (url.startsWith("/")) {
                // Same-origin path only: no "//host", no scheme, no authority.
                if (url.startsWith("//") || uri.getScheme() != null || uri.getRawAuthority() != null) {
                    return null;
                }
                return url;
            }
            if (uri.getRawUserInfo() != null) {
                return null;
            }
        } catch (URISyntaxException e) {
            return null;
        }
        return checkURL(url);
    }

    public static void main(String[] args) {
    }

}