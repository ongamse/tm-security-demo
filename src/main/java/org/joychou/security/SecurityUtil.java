package org.joychou.security;

import org.joychou.config.WebConfig;
import org.joychou.security.ssrf.SSRFChecker;
import org.joychou.security.ssrf.SSRFException;
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
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


public class SecurityUtil {

    private static final Pattern FILTER_PATTERN = Pattern.compile("^[a-zA-Z0-9_/\\.-]+$");
    private static final Pattern ARG_PATTERN = Pattern.compile("^[a-zA-Z0-9_/\\.=-]+$");
    private static final Set<String> ALLOWED_COMMANDS = new HashSet<>(
            Arrays.asList("whoami", "id", "pwd", "date", "uname", "hostname", "uptime", "ls"));
    private static final Pattern REDIRECT_HOST_PATTERN =
            Pattern.compile("^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$");
    private static final Pattern AUTHORITY_PATTERN =
            Pattern.compile("^[a-zA-Z][a-zA-Z0-9+.-]*://([^/?#]*)(?:[/?#].*)?$");
    private static final Pattern HOSTNAME_PATTERN =
            Pattern.compile("^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*$");
    private static final Pattern REDIRECT_URL_PATTERN =
            Pattern.compile("^([a-zA-Z][a-zA-Z0-9+.-]*)://([^/?#]*)([^?#]*)(?:\\?([^#]*))?(?:#.*)?$");
    private static final Pattern IPV6_LITERAL_PATTERN = Pattern.compile("^\\[[0-9a-fA-F:.]+\\]$");
    private static final Pattern PORT_PATTERN = Pattern.compile("^[0-9]{0,5}$");
    private static Logger logger =LoggerFactory.getLogger(SecurityUtil.class);


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
        // Pure string based extraction: the untrusted value is never handed to java.net.URI / URL.
        if (url == null || url.isEmpty() || url.indexOf('\\') >= 0) {
            return "";
        }
        for (int i = 0; i < url.length(); i++) {
            char ch = url.charAt(i);
            if (Character.isISOControl(ch) || Character.isWhitespace(ch)) {
                return "";
            }
        }
        Matcher m = AUTHORITY_PATTERN.matcher(url);
        if (!m.matches()) {
            return "";
        }
        String authority = m.group(1);
        int at = authority.lastIndexOf('@');
        String hostPort = at >= 0 ? authority.substring(at + 1) : authority;

        String host;
        String port;
        if (hostPort.startsWith("[")) {
            int end = hostPort.indexOf(']');
            if (end < 0) {
                return "";
            }
            host = hostPort.substring(0, end + 1);
            port = hostPort.substring(end + 1);
            if (!IPV6_LITERAL_PATTERN.matcher(host).matches()) {
                return "";
            }
            if (!port.isEmpty() && !port.startsWith(":")) {
                return "";
            }
            port = port.isEmpty() ? "" : port.substring(1);
        } else {
            int colon = hostPort.indexOf(':');
            host = colon >= 0 ? hostPort.substring(0, colon) : hostPort;
            port = colon >= 0 ? hostPort.substring(colon + 1) : "";
            if (!HOSTNAME_PATTERN.matcher(host).matches()) {
                return "";
            }
        }
        if (!PORT_PATTERN.matcher(port).matches()) {
            return "";
        }
        return host.toLowerCase();
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
            logger.error("safeRedirect check failed: {}", LogSafe.errorName(e));
            return null;
        }
    }


    /**
     * Build a redirect target for an untrusted url. The returned value is NOT the request string:
     * scheme is a server-side constant, the host is composed from a configured safe domain entry
     * (plus a strictly validated sub-domain prefix), and path/query are re-encoded from the parsed
     * components. User info, custom ports, fragments and control chars are rejected or dropped.
     *
     * @param url untrusted url
     * @return rebuilt safe absolute url, or null if the url must not be redirected to
     */
    public static String safeRedirectTarget(String url) {
        if (url == null || hasHeaderControlChars(url) || checkURL(url) == null) {
            return null;
        }
        // The untrusted string is split with a strict pattern; it is never parsed by java.net.URI/URL.
        Matcher m = REDIRECT_URL_PATTERN.matcher(url);
        if (!m.matches()) {
            return null;
        }

        final String scheme;
        if ("https".equalsIgnoreCase(m.group(1))) {
            scheme = "https";
        } else if ("http".equalsIgnoreCase(m.group(1))) {
            scheme = "http";
        } else {
            return null;
        }

        String authority = m.group(2);
        if (authority.indexOf('@') >= 0 || authority.indexOf(':') >= 0) {
            return null; // no user info, no custom port, no IPv6 literal
        }

        String host = authority.toLowerCase();
        if (!REDIRECT_HOST_PATTERN.matcher(host).matches()) {
            return null;
        }

        String safeHost = null;
        for (String safeDomain : WebConfig.getSafeDomains()) {
            String domain = safeDomain.toLowerCase();
            if (host.equals(domain)) {
                safeHost = domain;
                break;
            }
            if (host.endsWith("." + domain)) {
                safeHost = host.substring(0, host.length() - domain.length()) + domain;
                break;
            }
        }
        if (safeHost == null) {
            return null;
        }

        try {
            String path = SSRFChecker.decodeComponent(m.group(3));
            if (path.isEmpty()) {
                path = "/";
            }
            String query = m.group(4) == null ? null : SSRFChecker.decodeComponent(m.group(4));
            // The multi-argument constructor quotes any illegal character (including CR/LF).
            return new URI(scheme, null, safeHost, -1, path, query, null).toASCIIString();
        } catch (URISyntaxException | SSRFException e) {
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
                logger.info("Unsupported encoding exception: {}", LogSafe.fingerprint(filepath));
                return null;
            } catch (Exception e) {
                logger.info("pathFilter decode failed: {}", LogSafe.errorName(e));
                return null;
            }
        }

        if (temp.contains("..") || temp.charAt(0) == '/') {
            return null;
        }

        return filepath;
    }


    /**
     * Check whether a value contains CR, LF or any other ISO control character, which must never
     * be written into an HTTP response header (CRLF / header injection).
     *
     * @param value header value candidate
     * @return true if the value contains a control character; false for null or clean values
     */
    public static boolean hasHeaderControlChars(String value) {
        if (value == null) {
            return false;
        }
        for (int i = 0; i < value.length(); i++) {
            char ch = value.charAt(i);
            if (Character.isISOControl(ch)) {
                return true;
            }
        }
        return false;
    }


    /**
     * Return the Origin only if it is free of control characters and passes the url allowlist.
     *
     * @param origin value of the request Origin header
     * @return the origin if it is safe to reflect in Access-Control-Allow-Origin, otherwise null
     */
    public static String checkOrigin(String origin) {
        return allowedOriginOrNull(origin);
    }


    /**
     * Look up a request Origin in the fixed, server-side list of allowed origins and return the
     * MATCHING SERVER-SIDE CONSTANT (never the request string). The list is built from the
     * configured safe domains (WebConfig / url_safe_domain.xml) as exact scheme://host origins
     * for http and https. The literal "null" origin, origins with control characters, ports,
     * user info, paths or wildcards never match and block-listed domains are never returned.
     *
     * @param origin value of the request Origin header (untrusted)
     * @return the equal element of the server allowlist, or null if the origin is not allowed
     */
    public static String allowedOriginOrNull(String origin) {
        if (origin == null || origin.isEmpty() || hasHeaderControlChars(origin)
                || "null".equalsIgnoreCase(origin) || origin.indexOf('*') >= 0) {
            return null;
        }
        ArrayList<String> blockDomains = WebConfig.getBlockDomains();
        // server-side allowlist: key and value are both built from the configured safe domains
        Map<String, String> allowedOrigins = new HashMap<String, String>();
        for (String safeDomain : WebConfig.getSafeDomains()) {
            if (safeDomain == null || safeDomain.isEmpty()) {
                continue;
            }
            String domain = safeDomain.toLowerCase();
            if (blockDomains.contains(domain)) {
                continue;
            }
            for (String scheme : new String[]{"https://", "http://"}) {
                String candidate = scheme + domain;
                allowedOrigins.put(candidate, candidate);
            }
        }
        // the returned value is the server-side map value, never the request string
        return allowedOrigins.get(origin);
    }


    /**
     * Make a file name safe for use inside a Content-Disposition header: control characters,
     * whitespace, quotes, semicolons, commas and backslashes are replaced with an underscore.
     *
     * @param fileName file name candidate
     * @return sanitized file name
     */
    public static String sanitizeHeaderFileName(String fileName) {
        if (fileName == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder(fileName.length());
        for (int i = 0; i < fileName.length(); i++) {
            char ch = fileName.charAt(i);
            if (Character.isISOControl(ch) || Character.isWhitespace(ch)
                    || ch == '"' || ch == ';' || ch == ',' || ch == '\\') {
                sb.append('_');
            } else {
                sb.append(ch);
            }
        }
        return sb.toString();
    }


    public static String cmdFilter(String input) {
        if (!FILTER_PATTERN.matcher(input).matches()) {
            return null;
        }

        return input;
    }


    /**
     * Split a user supplied command line into an argv array, but only if the program is on a
     * strict allowlist and every argument consists of safe characters only. The result must be
     * executed without a shell (ProcessBuilder with argv).
     *
     * @param cmd user supplied command line
     * @return argv array, or null if the command is not allowed
     */
    public static String[] cmdAllowlistArgv(String cmd) {
        if (cmd == null) {
            return null;
        }
        String trimmed = cmd.trim();
        if (trimmed.isEmpty()) {
            return null;
        }
        String[] argv = trimmed.split("\\s+");
        if (!ALLOWED_COMMANDS.contains(argv[0])) {
            return null;
        }
        for (int i = 1; i < argv.length; i++) {
            if (!ARG_PATTERN.matcher(argv[i]).matches()) {
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