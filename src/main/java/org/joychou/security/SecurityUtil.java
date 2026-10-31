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
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;


public class SecurityUtil {

    private static final Pattern FILTER_PATTERN = Pattern.compile("^[a-zA-Z0-9_/\\.-]+$");
    private static final Pattern HOST_PATTERN = Pattern.compile("^[a-zA-Z0-9._-]+$");
    private static final Set<String> ALLOWED_COMMANDS = new HashSet<>(
            Arrays.asList("whoami", "id", "date", "pwd", "uname", "hostname", "ls"));
    private static Logger logger = LoggerFactory.getLogger(SecurityUtil.class);


    /**
     * Determine if the URL starts with HTTP.
     *
     * @param url url
     * @return true or false
     */
    public static boolean isHttp(String url) {
        return url != null && (url.startsWith("http://") || url.startsWith("https://"));
    }


    /**
     * Get http url host.
     *
     * @param url url
     * @return host
     */
    public static String gethost(String url) {
        // The value is only split into strings for allowlist comparison; it is never turned into a
        // URL/URI object and no connection is ever opened from it.
        if (url == null || url.length() > 2048) {
            return "";
        }
        for (int i = 0; i < url.length(); i++) {
            char c = url.charAt(i);
            if (c <= 0x20 || c == 0x7f || c == '\\') {
                return "";
            }
        }
        int schemeEnd = url.indexOf("://");
        if (schemeEnd <= 0) {
            return "";
        }
        for (int i = 0; i < schemeEnd; i++) {
            char c = url.charAt(i);
            boolean ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
                    || (i > 0 && ((c >= '0' && c <= '9') || c == '+' || c == '-' || c == '.'));
            if (!ok) {
                return "";
            }
        }
        int authorityStart = schemeEnd + 3;
        int authorityEnd = url.length();
        for (int i = authorityStart; i < url.length(); i++) {
            char c = url.charAt(i);
            if (c == '/' || c == '?' || c == '#') {
                authorityEnd = i;
                break;
            }
        }
        String authority = url.substring(authorityStart, authorityEnd);
        // User info in the authority is never accepted: fail closed with an empty host.
        if (authority.isEmpty() || authority.indexOf('@') != -1) {
            return "";
        }
        String host;
        String port = "";
        if (authority.startsWith("[")) {
            int close = authority.indexOf(']');
            if (close < 0) {
                return "";
            }
            host = authority.substring(0, close + 1);
            String rest = authority.substring(close + 1);
            if (!rest.isEmpty()) {
                if (rest.charAt(0) != ':') {
                    return "";
                }
                port = rest.substring(1);
            }
        } else {
            int colon = authority.indexOf(':');
            if (colon >= 0) {
                host = authority.substring(0, colon);
                port = authority.substring(colon + 1);
            } else {
                host = authority;
            }
            if (!HOST_PATTERN.matcher(host).matches()) {
                return "";
            }
        }
        if (!port.isEmpty() && (port.length() > 5 || !port.chars().allMatch(Character::isDigit))) {
            return "";
        }
        return host.isEmpty() ? "" : host.toLowerCase(java.util.Locale.ROOT);
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


    public static String cmdFilter(String input) {
        if (!FILTER_PATTERN.matcher(input).matches()) {
            return null;
        }

        return input;
    }


    /**
     * Split a user supplied command line into an argv array for a no-shell exec.
     * The executable must be in a fixed allowlist and every argument must match
     * {@link #FILTER_PATTERN}. No shell is involved, so metacharacters are never interpreted.
     *
     * @param cmd user supplied command line, e.g. "ls -la /tmp"
     * @return argv array, or null if the command is empty, not allowlisted or has an illegal argument
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
        if (tokens.length > 4) {
            return null;
        }
        // The returned argv is rebuilt only from server-side constants: the request value is used
        // purely as a lookup key and never flows into the process arguments.
        List<String> argv = new ArrayList<>();
        String executable = lookupExecutable(tokens[0]);
        if (executable == null) {
            return null;
        }
        argv.add(executable);
        for (int i = 1; i < tokens.length; i++) {
            String arg = lookupFlag(tokens[i]);
            if (arg == null) {
                arg = lookupDirectory(tokens[i]);
            }
            if (arg == null) {
                return null;
            }
            argv.add(arg);
        }
        return argv.toArray(new String[0]);
    }


    private static String lookupExecutable(String key) {
        switch (key) {
            case "whoami":
                return "whoami";
            case "id":
                return "id";
            case "date":
                return "date";
            case "pwd":
                return "pwd";
            case "uname":
                return "uname";
            case "hostname":
                return "hostname";
            case "ls":
                return "ls";
            default:
                return null;
        }
    }


    private static String lookupFlag(String key) {
        switch (key) {
            case "-a":
                return "-a";
            case "-l":
                return "-l";
            case "-la":
                return "-la";
            case "-al":
                return "-al";
            default:
                return null;
        }
    }


    /**
     * Map a user supplied directory to a fixed server-side directory constant.
     *
     * @param key user supplied directory
     * @return the matching constant, or null if the directory is not in the fixed allowlist
     */
    public static String lookupDirectory(String key) {
        if (key == null) {
            return null;
        }
        switch (key) {
            case "/tmp":
                return "/tmp";
            case "/var/tmp":
                return "/var/tmp";
            case "/var/log":
                return "/var/log";
            case "/usr/share":
                return "/usr/share";
            case ".":
                return ".";
            default:
                return null;
        }
    }


    /**
     * Map a user supplied Host header to a fixed server-side host constant.
     *
     * @param key user supplied host
     * @return the matching constant, or null if the host is not in the fixed allowlist
     */
    public static String lookupHost(String key) {
        if (key == null) {
            return null;
        }
        switch (key.toLowerCase(java.util.Locale.ROOT)) {
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
     * Remove CR, LF and NUL characters so that a value is safe to write into an
     * HTTP response header (prevents header injection / response splitting).
     *
     * @param value untrusted header value
     * @return the value without CR/LF/NUL; null stays null
     */
    public static String stripCRLF(String value) {
        if (value == null) {
            return null;
        }
        return value.replaceAll("[\\r\\n\\u0000]", "");
    }

    /**
     * Validate an untrusted redirect target. A target is accepted only when it is either
     * a same-site absolute path (e.g. /a/b, but not scheme-relative // or /\) or an
     * http(s) URL whose host passes {@link #checkURL(String)}. Targets containing
     * backslashes or control characters (CR/LF/NUL, whitespace tricks) are rejected.
     *
     * @param url untrusted redirect target
     * @return the validated target, or null when it must not be used for a redirect
     */
    public static String safeRedirectUrl(String url) {
        if (url == null || url.isEmpty()) {
            return null;
        }
        for (int i = 0; i < url.length(); i++) {
            char c = url.charAt(i);
            if (c == '\\' || c <= 0x20 || c == 0x7f) {
                return null;
            }
        }

        // Same-site relative path: must start with a single slash and carry no authority.
        if (url.startsWith("/")) {
            if (url.startsWith("//")) {
                return null;
            }
            return url;
        }

        // Absolute URL: must be on the project's domain whitelist.
        return checkURL(url);
    }

    public static void main(String[] args) {
    }

}