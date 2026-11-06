package org.joychou.security;

import org.joychou.config.WebConfig;
import org.joychou.security.ssrf.SSRFChecker;
import org.joychou.security.ssrf.SocketHook;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


public class SecurityUtil {

    private static final Pattern FILTER_PATTERN = Pattern.compile("^[a-zA-Z0-9_/\\.-]+$");
    private static final Pattern HOST_PATTERN = Pattern.compile("^[a-zA-Z0-9][a-zA-Z0-9.-]*(:[0-9]{1,5})?$");
    private static final Pattern HTTP_HOST_URL_PATTERN = Pattern.compile(
            "^https?://((?:[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?)|(?:\\[[0-9A-Fa-f:.]+\\]))"
                    + "(?::[0-9]{1,5})?(?:[/?#][^\\s\\\\@]*)?$",
            Pattern.CASE_INSENSITIVE);
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
        if (url == null) {
            return "";
        }
        // Strict http(s)://host[:port][/path][?query][#fragment] only: no userinfo, backslash,
        // whitespace or control characters, so the host cannot be parsed differently by a client.
        Matcher m = HTTP_HOST_URL_PATTERN.matcher(url);
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
     * Validate an untrusted redirect destination. Only two shapes are accepted: an http(s) url whose
     * parsed host passes {@link #checkURL(String)} (safe/block domain config), or a same-site
     * relative path such as <code>/a/b</code>. Protocol-relative (<code>//host</code>), backslash and
     * control character payloads are rejected.
     *
     * @param url untrusted redirect target
     * @return the target without control characters if allowed, otherwise null
     */
    public static String safeRedirectUrl(String url) {
        if (url == null || url.isEmpty()) {
            return null;
        }
        String clean = cRlfFilter(url);
        if (!clean.equals(url) || clean.indexOf('\\') != -1) {
            return null;
        }
        if (clean.startsWith("/")) {
            return clean.startsWith("//") ? null : clean;
        }
        return checkURL(clean);
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
     * Resolve an untrusted path against a base directory and confine the result to that directory.
     * The result is absolute and normalized; it must be strictly inside baseDir.
     *
     * @param baseDir  trusted base directory
     * @param userPath untrusted file name or path (relative to baseDir, or absolute inside baseDir)
     * @return the confined path, or null if the path is empty, malformed or escapes baseDir
     */
    public static Path resolveInDir(String baseDir, String userPath) {
        if (baseDir == null || userPath == null || userPath.isEmpty() || userPath.indexOf('\0') != -1) {
            return null;
        }
        try {
            Path base = Paths.get(baseDir).toAbsolutePath().normalize();
            Path resolved = base.resolve(userPath).normalize();
            if (!resolved.startsWith(base) || resolved.equals(base)) {
                return null;
            }
            return resolved;
        } catch (InvalidPathException e) {
            logger.info("Invalid path: " + e.getReason());
            return null;
        }
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
                logger.info("Unsupported encoding exception: " + logSafe(filepath));
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


    /**
     * Remove CR, LF and all other control characters (including DEL) from a value that is going
     * to be placed into an HTTP response header or cookie, to prevent header injection / response
     * splitting.
     *
     * @param value untrusted value, may be null
     * @return the value without control characters, or null if value is null
     */
    public static String cRlfFilter(String value) {
        if (value == null) {
            return null;
        }
        StringBuilder sb = new StringBuilder(value.length());
        for (int i = 0; i < value.length(); i++) {
            char ch = value.charAt(i);
            if (ch >= 0x20 && ch != 0x7f) {
                sb.append(ch);
            }
        }
        return sb.toString();
    }


    /**
     * Neutralize an untrusted value before it is written to a log, to prevent log forging.
     * CR, LF and all other control characters (including DEL) are replaced with '_'.
     *
     * @param value untrusted value, may be null
     * @return the sanitized value, or the string "null" if value is null
     */
    public static String logSafe(String value) {
        if (value == null) {
            return "null";
        }
        StringBuilder sb = new StringBuilder(value.length());
        for (int i = 0; i < value.length(); i++) {
            char ch = value.charAt(i);
            sb.append((ch < 0x20 || ch == 0x7f || ch == 0x85 || ch == 0x2028 || ch == 0x2029) ? '_' : ch);
        }
        return sb.toString();
    }


    public static String cmdFilter(String input) {
        if (input == null || !FILTER_PATTERN.matcher(input).matches()) {
            return null;
        }

        return input;
    }


    /**
     * Fixed set of argument-less commands that may be requested by name. Anything else is rejected.
     */
    private static final Set<String> ALLOWED_COMMANDS = Collections.unmodifiableSet(
            new HashSet<>(Arrays.asList("whoami", "id", "date", "uname", "hostname", "pwd")));


    /**
     * Allowlist a user supplied command name. The returned value is a constant from the
     * allowlist, so it can be run as a single argv element without a shell.
     *
     * @param cmd untrusted command name
     * @return the allowlisted command, or null if it is not allowed
     */
    public static String allowedCommand(String cmd) {
        if (cmd == null) {
            return null;
        }
        String trimmed = cmd.trim();
        return ALLOWED_COMMANDS.contains(trimmed) ? trimmed : null;
    }


    /**
     * Validate a Host header value (host name or IPv4 with optional port) so it is safe to use as
     * a single argv element.
     *
     * @param host untrusted host value
     * @return the host if it is well formed, otherwise null
     */
    public static String hostFilter(String host) {
        if (host == null || !HOST_PATTERN.matcher(host).matches()) {
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