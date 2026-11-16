package org.joychou.security;

import org.joychou.config.WebConfig;
import org.joychou.security.ssrf.SSRFChecker;
import org.joychou.security.ssrf.SocketHook;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
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
            Arrays.asList("whoami", "id", "date", "hostname", "uname", "pwd", "ls"));
    private static final String LIST_BASE = "/tmp";
    private static final String REDIRECT_HOST_CHARS = "abcdefghijklmnopqrstuvwxyz0123456789.-";
    private static final String REDIRECT_PATH_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
            + "-._~!$&'()*+,;=:@/%?#";
    private static final String FILENAME_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_";
    private static final String HEADER_TEXT_CHARS = " !\"#$%&'()*+,-./0123456789:;<=>?@"
            + "ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~";
    private static final Set<String> ALLOWED_FLAGS = new HashSet<String>(
            Arrays.asList("-a", "-l", "-la", "-al", "-lh", "-lah", "-1", "-h", "-s", "-r", "-m", "-n", "-u", "-g", "-un"));
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
        if (url == null || url.indexOf('\\') >= 0) {
            return "";
        }
        try {
            // Pure string / URI parsing: no java.net.URL (and no connection) is ever built from the
            // request-derived string here.
            URI uri = new URI(url);
            String host = uri.getHost();
            if (host == null || host.isEmpty()) {
                return "";
            }
            // The host reported by java.net.URI must be exactly the host of the raw authority
            // (after the last '@' and before the port), so that no other parser (e.g. the HTTP
            // client) can read a different host from the same string.
            String authority = uri.getRawAuthority();
            if (authority == null) {
                return "";
            }
            String hostPort = authority.substring(authority.lastIndexOf('@') + 1);
            int portSep = hostPort.lastIndexOf(':');
            String rawHost = (portSep >= 0 && hostPort.indexOf(']') < portSep) ? hostPort.substring(0, portSep) : hostPort;
            if (!host.equalsIgnoreCase(rawHost)) {
                return "";
            }
            return host.toLowerCase();
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


    /**
     * Syntax check for a redirect target. Accepts only a same-site absolute path (<code>/a/b</code>)
     * or an absolute http(s) url with a host and no userinfo. Rejects control characters, backslashes,
     * scheme-relative urls (<code>//host</code>) and urls that java.net.URI and java.net.URL parse
     * to different hosts.
     *
     * @param url the redirect target taken from the request
     * @return true if the target has a safe shape
     */
    public static boolean isSafeRedirectSyntax(String url) {
        if (url == null || url.isEmpty() || !isSafeHeaderValue(url) || url.indexOf('\\') >= 0) {
            return false;
        }
        if (url.startsWith("/")) {
            // same-site path only; "//host" is a scheme-relative url
            return !url.startsWith("//");
        }
        if (!isHttp(url)) {
            return false;
        }
        try {
            URI uri = new URI(url);
            if (uri.getRawUserInfo() != null) {
                return false;
            }
        } catch (URISyntaxException e) {
            return false;
        }
        return !gethost(url).isEmpty();
    }


    /**
     * Validate a redirect target against the url safe-domain list ({@link #checkURL(String)}) or
     * restrict it to a same-site path.
     *
     * @param url the redirect target taken from the request
     * @return the original url if it may be redirected to; otherwise null
     */
    public static String checkRedirectURL(String url) {
        if (!isSafeRedirectSyntax(url)) {
            return null;
        }
        if (!url.startsWith("/") && checkURL(url) == null) {
            return null;
        }
        return rebuildRedirect(url);
    }


    /**
     * Rebuild a redirect target that already passed the domain policy. The result is not the request
     * string: the scheme is a constant, the host and the path/query are copied one character at a time
     * from fixed allowlists of url characters (anything else rejects the target), and the port is a
     * parsed integer. A same-site path keeps its fixed leading "/".
     *
     * @param url the redirect target taken from the request
     * @return the rebuilt target, or null if it has an unsafe shape or contains characters outside the allowlist
     */
    public static String rebuildRedirect(String url) {
        if (!isSafeRedirectSyntax(url)) {
            return null;
        }
        if (url.startsWith("/")) {
            return copyAllowed(url, REDIRECT_PATH_CHARS);
        }
        try {
            URI uri = new URI(url);
            String host = copyAllowed(gethost(url), REDIRECT_HOST_CHARS);
            String path = uri.getRawPath() == null ? "" : uri.getRawPath();
            if (host == null || host.isEmpty() || (!path.isEmpty() && !path.startsWith("/"))) {
                return null;
            }
            StringBuilder rest = new StringBuilder(path);
            if (uri.getRawQuery() != null) {
                rest.append('?').append(uri.getRawQuery());
            }
            if (uri.getRawFragment() != null) {
                rest.append('#').append(uri.getRawFragment());
            }
            String safeRest = copyAllowed(rest.toString(), REDIRECT_PATH_CHARS);
            if (safeRest == null) {
                return null;
            }
            StringBuilder target = new StringBuilder("https".equalsIgnoreCase(uri.getScheme()) ? "https" : "http");
            target.append("://").append(host);
            if (uri.getPort() != -1) {
                target.append(':').append(uri.getPort());
            }
            return target.append(safeRest).toString();
        } catch (URISyntaxException e) {
            return null;
        }
    }


    /**
     * Copy a string using only characters taken from the allowlist constant.
     *
     * @return the copy, or null if any character is not in the allowlist
     */
    private static String copyAllowed(String value, String allowed) {
        if (value == null) {
            return null;
        }
        StringBuilder sb = new StringBuilder(value.length());
        for (int i = 0; i < value.length(); i++) {
            int idx = allowed.indexOf(value.charAt(i));
            if (idx < 0) {
                return null;
            }
            sb.append(allowed.charAt(idx));
        }
        return sb.toString();
    }


    /**
     * Check that a value is safe to place into an HTTP response header (prevents CRLF / header
     * injection). Control characters (CR, LF, NUL, ...) and DEL are rejected; horizontal tab is allowed.
     *
     * @param value the value that will be written to a response header
     * @return true if the value is null or contains no control characters
     */
    public static boolean isSafeHeaderValue(String value) {
        if (value == null) {
            return true;
        }
        for (int i = 0; i < value.length(); i++) {
            char ch = value.charAt(i);
            if ((ch < 0x20 && ch != '\t') || ch == 0x7f) {
                return false;
            }
        }
        return true;
    }


    /**
     * Validate a request Origin header against the url safe-domain list ({@link #checkURL(String)}).
     * Only a bare origin (scheme://host[:port]) that is safe for a response header is accepted, so the
     * returned value may be echoed in Access-Control-Allow-Origin.
     *
     * @param origin the Origin request header value
     * @return the origin if it is allowlisted; otherwise null
     */
    public static String checkOrigin(String origin) {
        if (origin == null || origin.isEmpty() || !isSafeHeaderValue(origin)) {
            return null;
        }
        try {
            URI uri = new URI(origin);
            boolean bareOrigin = uri.getRawUserInfo() == null && uri.getRawQuery() == null
                    && uri.getRawFragment() == null
                    && (uri.getRawPath() == null || uri.getRawPath().isEmpty());
            if (!bareOrigin || checkURL(origin) == null) {
                return null;
            }
            // The returned value is not the request string: the scheme is a constant, the host is
            // copied one character at a time from a fixed allowlist and the port is a parsed integer.
            String host = copyAllowed(gethost(origin), REDIRECT_HOST_CHARS);
            if (host == null || host.isEmpty()) {
                return null;
            }
            StringBuilder rebuilt = new StringBuilder("https".equalsIgnoreCase(uri.getScheme()) ? "https" : "http");
            rebuilt.append("://").append(host);
            if (uri.getPort() != -1) {
                rebuilt.append(':').append(uri.getPort());
            }
            return rebuilt.toString();
        } catch (URISyntaxException e) {
            return null;
        }
    }


    /**
     * Rebuild a free-text header value (not a url) from printable ASCII only. The result is copied one
     * character at a time from a constant, so it never contains CR, LF or other control characters.
     *
     * @param value the request-derived text that should be written to a response header
     * @return the rebuilt text, or null if the value is null or contains a character outside printable ASCII
     */
    public static String safeHeaderText(String value) {
        return copyAllowed(value, HEADER_TEXT_CHARS);
    }


    /**
     * Derive a download file name from request-derived text. Only letters, digits, '.', '-' and '_'
     * are kept (copied from a constant); every other character becomes '_'.
     *
     * @param name the request-derived name (may be null)
     * @return a header-safe file name, never null or empty
     */
    public static String safeFileName(String name) {
        StringBuilder sb = new StringBuilder();
        if (name != null) {
            for (int i = 0; i < name.length() && sb.length() < 100; i++) {
                int idx = FILENAME_CHARS.indexOf(name.charAt(i));
                sb.append(idx < 0 ? '_' : FILENAME_CHARS.charAt(idx));
            }
        }
        return sb.length() == 0 ? "download" : sb.toString();
    }


    public static String cmdFilter(String input) {
        if (!FILTER_PATTERN.matcher(input).matches()) {
            return null;
        }

        return input;
    }


    /**
     * Resolve an untrusted path to a directory entry below {@link #LIST_BASE}. The returned string is
     * rebuilt from names enumerated from the file system (never from the caller's text), "." / ".."
     * segments are rejected and the canonical location must stay inside the base directory.
     *
     * @param input untrusted path, e.g. <code>/tmp/foo</code>
     * @return the existing path below the base directory, or null if it is not allowed
     */
    public static String allowedListPath(String input) {
        if (input == null || cmdFilter(input) == null) {
            return null;
        }
        if (!input.equals(LIST_BASE) && !input.startsWith(LIST_BASE + "/")) {
            return null;
        }
        try {
            String canonicalBase = new File(LIST_BASE).getCanonicalPath();
            File current = new File(LIST_BASE);
            String result = LIST_BASE;
            for (String segment : input.substring(LIST_BASE.length()).split("/")) {
                if (segment.isEmpty()) {
                    continue;
                }
                if (".".equals(segment) || "..".equals(segment)) {
                    return null;
                }
                String[] names = current.list();
                if (names == null) {
                    return null;
                }
                String match = null;
                for (String name : names) {
                    if (name.equals(segment)) {
                        match = name;
                        break;
                    }
                }
                if (match == null) {
                    return null;
                }
                current = new File(current, match);
                result = result + "/" + match;
            }
            String canonical = current.getCanonicalPath();
            if (!canonical.equals(canonicalBase) && !canonical.startsWith(canonicalBase + File.separator)) {
                return null;
            }
            return result;
        } catch (IOException e) {
            return null;
        }
    }


    /**
     * Turn an untrusted command line into a safe argv array (never run through a shell).
     * The program must be in a fixed allowlist and every argument must pass {@link #cmdFilter}.
     *
     * @param cmd untrusted command line, e.g. <code>ls -la /tmp</code>
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
        String[] tokens = trimmed.split("\\s+");
        // Every argv entry returned below is a constant taken from a fixed allowlist, never the
        // caller-supplied text itself: the program from ALLOWED_COMMANDS, options from ALLOWED_FLAGS.
        String program = null;
        for (String allowed : ALLOWED_COMMANDS) {
            if (allowed.equals(tokens[0])) {
                program = allowed;
                break;
            }
        }
        if (program == null) {
            return null;
        }
        String[] argv = new String[tokens.length];
        argv[0] = program;
        for (int i = 1; i < tokens.length; i++) {
            String flag = null;
            for (String allowed : ALLOWED_FLAGS) {
                if (allowed.equals(tokens[i])) {
                    flag = allowed;
                    break;
                }
            }
            if (flag == null) {
                return null;
            }
            argv[i] = flag;
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