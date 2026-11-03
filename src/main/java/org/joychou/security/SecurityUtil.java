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
import java.util.HashSet;
import java.util.Set;
import java.util.regex.Pattern;


public class SecurityUtil {

    private static final Pattern FILTER_PATTERN = Pattern.compile("^[a-zA-Z0-9_/\\.-]+$");
    private static final Set<String> ALLOWED_COMMANDS = new HashSet<String>(
            Arrays.asList("whoami", "id", "hostname", "uname", "date", "pwd"));
    // An argument must start with an alphanumeric char so it can never be parsed as an option.
    private static final Pattern CMD_ARG_PATTERN = Pattern.compile("^[a-zA-Z0-9][a-zA-Z0-9_./=:-]*$");
    private static final int MAX_CMD_ARGS = 8;
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
        if (!isHttp(url)) {
            return "";
        }
        try {
            // java.net.URI is strict (rejects backslashes etc.), so the host cannot differ from
            // what the http client will connect to. User info is never accepted.
            URI uri = new URI(url);
            if (uri.getRawUserInfo() != null || uri.getHost() == null) {
                return "";
            }
            return uri.getHost().toLowerCase();
        } catch (URISyntaxException e) {
            return "";
        }
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
        for (int i = 0; i < url.length(); i++) {
            char c = url.charAt(i);
            if (Character.isISOControl(c) || c == '\\') {
                return null;
            }
        }
        if (url.charAt(0) == '/') {
            if (url.length() > 1 && url.charAt(1) == '/') {
                return null;
            }
            try {
                URI uri = new URI(url);
                if (uri.getScheme() != null || uri.getRawAuthority() != null) {
                    return null;
                }
                return url;
            } catch (URISyntaxException e) {
                return null;
            }
        }
        return checkURL(url);
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
        if (url == null) {
            return null;
        }
        for (int i = 0; i < url.length(); i++) {
            char c = url.charAt(i);
            if (Character.isISOControl(c) || c == '\\') {
                return null;
            }
        }
        String host = gethost(url);
        if (host.isEmpty()) {
            return null;
        }
        for (String domain : domains) {
            if (host.equals(domain) || host.endsWith("." + domain)) {
                return url;
            }
        }
        return null;
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
     * Validate a CORS request Origin header value. The value must be a bare http(s) origin
     * (scheme://host[:port], no user info, path, query or fragment, no control characters or
     * backslashes) whose strictly parsed host is allowed by {@link #checkURL(String)}.
     *
     * @param origin the value of the Origin request header
     * @return the original origin when it is allowed; null otherwise (including the literal "null" origin)
     */
    public static String checkOrigin(String origin) {
        if (origin == null || origin.isEmpty()) {
            return null;
        }
        for (int i = 0; i < origin.length(); i++) {
            char c = origin.charAt(i);
            if (Character.isISOControl(c) || c == '\\' || Character.isWhitespace(c)) {
                return null;
            }
        }
        try {
            URI uri = new URI(origin);
            String path = uri.getRawPath();
            if (uri.getRawUserInfo() != null || uri.getRawQuery() != null
                    || uri.getRawFragment() != null || (path != null && !path.isEmpty())) {
                return null;
            }
        } catch (URISyntaxException e) {
            return null;
        }
        return checkURL(origin);
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
        if (input == null || !FILTER_PATTERN.matcher(input).matches()) {
            return null;
        }

        return input;
    }


    /**
     * Convert a user supplied command line to an argv array that is safe to pass to
     * ProcessBuilder / Runtime.exec(String[]) without a shell. The program must be in a fixed
     * allowlist and every argument must match a strict character set and not start with '-'.
     *
     * @param cmd the user supplied command line
     * @return argv array, or null if the command is not allowed
     */
    public static String[] cmdToArgv(String cmd) {
        if (cmd == null) {
            return null;
        }
        String[] parts = cmd.trim().split("\\s+");
        if (parts.length == 0 || parts.length > MAX_CMD_ARGS || !ALLOWED_COMMANDS.contains(parts[0])) {
            return null;
        }
        for (int i = 1; i < parts.length; i++) {
            if (!CMD_ARG_PATTERN.matcher(parts[i]).matches()) {
                return null;
            }
        }
        return parts;
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