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
import java.util.Arrays;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


public class SecurityUtil {

    private static final Pattern FILTER_PATTERN = Pattern.compile("^[a-zA-Z0-9_/\\.-]+$");
    private static final Pattern JDBC_URL_PATTERN = Pattern.compile(
            "^jdbc:([a-z0-9]+)://([A-Za-z0-9.-]+)(?::([0-9]{1,5}))?/([A-Za-z0-9_.-]+)$");

    /** Characters allowed after the authority of an http(s) url (path, query and fragment). */
    private static final String URL_TAIL_CHARS =
            "[A-Za-z0-9._~!$&'()*+,;=:@%/?#-]*";
    /** Strict absolute http(s) url: explicit host (name or bracketed IPv6), optional port, no user-info. */
    private static final Pattern HTTP_URL_PATTERN = Pattern.compile(
            "^(https?)://(\\[[0-9A-Fa-f:.]+\\]|[A-Za-z0-9][A-Za-z0-9.-]*)(?::([0-9]{1,5}))?([/?#]"
                    + URL_TAIL_CHARS + ")?$", Pattern.CASE_INSENSITIVE);
    /** Same-site relative path: single leading slash, no authority, no backslash. */
    private static final Pattern RELATIVE_PATH_PATTERN = Pattern.compile(
            "^/(?!/)[A-Za-z0-9._~!$&'()*+,;=:@%/?#-]*$");
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
        ParsedUrl parsed = parseHttpUrl(url);
        return parsed == null ? "" : parsed.getHost();
    }


    /**
     * The single place where an untrusted absolute http(s) url string is parsed. The result
     * carries the individual components so that callers can build outgoing urls from them
     * instead of passing the raw input on.
     */
    public static final class ParsedUrl {
        private final String scheme;
        private final String host;
        private final int port;
        private final String file;

        private ParsedUrl(String scheme, String host, int port, String file) {
            this.scheme = scheme;
            this.host = host;
            this.port = port;
            this.file = file;
        }

        /** @return "http" or "https" */
        public String getScheme() {
            return scheme;
        }

        /** @return lower-case host name, IPv4 literal or bracketed IPv6 literal */
        public String getHost() {
            return host;
        }

        /** @return explicit port, or -1 for the scheme default */
        public int getPort() {
            return port;
        }

        /** @return path and query (fragment removed); may be empty */
        public String getFile() {
            return file;
        }
    }


    /**
     * Strictly parse an absolute http(s) url: no whitespace/control characters, no backslashes,
     * no user-info, explicit host, valid port.
     *
     * @param url untrusted url, may be null
     * @return the parsed components or null if the url is not a well-formed http(s) url
     */
    public static ParsedUrl parseHttpUrl(String url) {
        if (url == null || url.length() > 2048 || containsUnsafeUrlChar(url)) {
            return null;
        }
        Matcher m = HTTP_URL_PATTERN.matcher(url);
        if (!m.matches()) {
            return null;
        }
        String scheme = "https".equalsIgnoreCase(m.group(1)) ? "https" : "http";
        String host = m.group(2).toLowerCase(Locale.ROOT);
        if (host.length() > 253 || host.contains("..")) {
            return null;
        }
        int port = -1;
        if (m.group(3) != null) {
            port = Integer.parseInt(m.group(3));
            if (port < 1 || port > 65535) {
                return null;
            }
        }
        String file = m.group(4) == null ? "" : m.group(4);
        int fragment = file.indexOf('#');
        if (fragment >= 0) {
            file = file.substring(0, fragment);
        }
        if (file.startsWith("?")) {
            file = "/" + file;
        }
        return new ParsedUrl(scheme, host, port, file);
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
        return SSRFChecker.safeUrl(url) != null;
    }

    /**
     * Single choke point for outbound http(s) requests built from untrusted input. The url is
     * parsed once ({@link #parseHttpUrl(String)}), the host is resolved and must not be internal,
     * and the returned url is assembled from the validated components.
     *
     * @param url untrusted url, may be null
     * @return the rebuilt url, or null if it is not an allowed outbound target
     */
    public static java.net.URL safeOutboundUrl(String url) {
        return SSRFChecker.safeUrl(url);
    }

    /**
     * Validate a user supplied JDBC url before it reaches DriverManager. Only
     * <code>jdbc:&lt;subprotocol&gt;://host[:port]/database</code> is accepted: no query
     * string, no driver properties (e.g. socketFactory), and the host must not
     * resolve to an internal address.
     *
     * @param jdbcUrl     user supplied jdbc url
     * @param subprotocol expected subprotocol, e.g. "postgresql" or "db2"
     * @return the jdbc url when safe, otherwise null
     */
    public static String safeJdbcUrl(String jdbcUrl, String subprotocol) {
        if (jdbcUrl == null || subprotocol == null) {
            return null;
        }
        Matcher m = JDBC_URL_PATTERN.matcher(jdbcUrl);
        if (!m.matches() || !subprotocol.equals(m.group(1))) {
            return null;
        }
        String host = SSRFChecker.safeHost(m.group(2));
        if (host == null) {
            return null;
        }
        String port = "";
        if (m.group(3) != null) {
            int p = Integer.parseInt(m.group(3));
            if (p < 1 || p > 65535) {
                return null;
            }
            port = ":" + p;
        }
        // Rebuilt from the validated components, not from the raw input.
        return "jdbc:" + subprotocol + "://" + host + port + "/" + m.group(4);
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
     * Map a user supplied command token to a fixed argv template for a no-shell spawn
     * (ProcessBuilder / Runtime.exec(String[])). The request value is only used as a
     * lookup key; the returned argv consists solely of compile-time constants.
     *
     * @param cmd user supplied command key, e.g. "whoami" or "uname -a"
     * @return fixed argv array, or null if the command is not allowed
     */
    public static String[] safeCommand(String cmd) {
        if (cmd == null) {
            return null;
        }
        switch (cmd.trim().replaceAll("\\s+", " ")) {
            case "whoami":
                return new String[]{"whoami"};
            case "id":
                return new String[]{"id"};
            case "date":
                return new String[]{"date"};
            case "hostname":
                return new String[]{"hostname"};
            case "uname":
                return new String[]{"uname"};
            case "uname -a":
                return new String[]{"uname", "-a"};
            case "pwd":
                return new String[]{"pwd"};
            case "uptime":
                return new String[]{"uptime"};
            default:
                return null;
        }
    }


    /**
     * Map a user supplied directory key to a fixed "ls" argv. Only allowlisted
     * directories are accepted; the request value is never part of the argv.
     *
     * @param path requested directory
     * @return fixed argv array, or null if the directory is not allowed
     */
    public static String[] safeListCommand(String path) {
        if (path == null) {
            return null;
        }
        switch (path) {
            case "/tmp":
                return new String[]{"ls", "-la", "--", "/tmp"};
            case "/var/tmp":
                return new String[]{"ls", "-la", "--", "/var/tmp"};
            case "/usr/share":
                return new String[]{"ls", "-la", "--", "/usr/share"};
            default:
                return null;
        }
    }


    /**
     * Map a user supplied host (e.g. the Host header) to a fixed "curl" argv. Only
     * allowlisted local hosts are accepted; the request value is never part of the argv.
     *
     * @param host requested host
     * @return fixed argv array, or null if the host is not allowed
     */
    public static String[] safeCurlCommand(String host) {
        if (host == null) {
            return null;
        }
        switch (host.trim().toLowerCase(Locale.ROOT)) {
            case "localhost":
                return new String[]{"curl", "--proto", "=http,https", "--", "http://localhost/"};
            case "localhost:8080":
                return new String[]{"curl", "--proto", "=http,https", "--", "http://localhost:8080/"};
            case "127.0.0.1":
                return new String[]{"curl", "--proto", "=http,https", "--", "http://127.0.0.1/"};
            case "127.0.0.1:8080":
                return new String[]{"curl", "--proto", "=http,https", "--", "http://127.0.0.1:8080/"};
            default:
                return null;
        }
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
     * Remove CR, LF and all other ISO control characters from a value before it is
     * placed in an HTTP response header (prevents header injection / response splitting).
     *
     * @param value untrusted header value, may be null
     * @return the value without control characters; null if value is null
     */
    public static String sanitizeHeaderValue(String value) {
        if (value == null) {
            return null;
        }
        StringBuilder sb = new StringBuilder(value.length());
        for (int i = 0; i < value.length(); i++) {
            char ch = value.charAt(i);
            if (!Character.isISOControl(ch) && ch != 0x2028 && ch != 0x2029) {
                sb.append(ch);
            }
        }
        return sb.toString();
    }

    /**
     * Strict syntax check for an absolute http(s) url: no whitespace/control characters,
     * no backslashes, parsed by {@link #parseHttpUrl(String)}, explicit host and no user-info.
     *
     * @param url untrusted url, may be null
     * @return true if the url is a well-formed absolute http(s) url
     */
    public static boolean isSafeUrlSyntax(String url) {
        return parseHttpUrl(url) != null;
    }

    /**
     * Validate an untrusted redirect target. Allowed targets are either a same-site relative
     * path (single leading slash; protocol-relative "//host" and backslash forms are rejected)
     * or an absolute http(s) url whose host passes {@link #checkURL(String)}.
     *
     * @param url untrusted redirect target, may be null
     * @return the original url when it is a safe redirect target; null otherwise
     */
    public static String safeRedirectUrl(String url) {
        if (url == null || url.isEmpty() || containsUnsafeUrlChar(url)) {
            return null;
        }
        if (url.startsWith("/")) {
            return RELATIVE_PATH_PATTERN.matcher(url).matches() ? url : null;
        }
        if (isSafeUrlSyntax(url) && checkURL(url) != null) {
            return url;
        }
        return null;
    }

    private static boolean containsUnsafeUrlChar(String url) {
        for (int i = 0; i < url.length(); i++) {
            char ch = url.charAt(i);
            if (ch <= 0x20 || ch == 0x7f || ch == '\\' || Character.isISOControl(ch)) {
                return true;
            }
        }
        return false;
    }

    public static void main(String[] args) {
    }

}