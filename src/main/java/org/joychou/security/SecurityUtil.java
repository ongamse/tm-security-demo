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
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;


public class SecurityUtil {

    private static final Pattern FILTER_PATTERN = Pattern.compile("^[a-zA-Z0-9_/\\.-]+$");
    private static final List<String> NO_ARG_COMMANDS = Arrays.asList("whoami", "id", "date", "uname", "hostname", "pwd");
    private static final List<String> ARG_COMMANDS = Arrays.asList("ls");
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
     * @return host, or empty string if the url is malformed or has no host
     */
    public static String gethost(String url) {
        try {
            URI uri = new URI(url);
            String host = uri.getHost();
            return host == null ? "" : host.toLowerCase();
        } catch (URISyntaxException | NullPointerException e) {
            return "";
        }
    }


    /**
     * Validate an untrusted JDBC url before it is handed to DriverManager.
     * The url must start with the expected prefix, must not carry driver properties
     * (query string / semicolon / ampersand / equals / userinfo / escapes, which are used to
     * load arbitrary classes or contact other hosts), and its host must be on the SSRF
     * safe host list.
     *
     * @param jdbcUrl untrusted jdbc url
     * @param prefix  required prefix, e.g. <code>jdbc:postgresql://</code>
     * @return true if the url is allowed
     */
    public static boolean checkJdbcUrl(String jdbcUrl, String prefix) {
        if (jdbcUrl == null || prefix == null || !jdbcUrl.startsWith(prefix)) {
            return false;
        }
        String rest = jdbcUrl.substring(prefix.length());
        for (char c : new char[]{'?', ';', '&', '=', '@', '%', '\\', ' '}) {
            if (rest.indexOf(c) != -1) {
                return false;
            }
        }
        String hostPort = rest.split("/", 2)[0];
        return checkSSRFByWhitehosts("https://" + hostPort + "/");
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
     * Resolve a user supplied path against a base directory and make sure the
     * result stays inside that base directory (including after symlink resolution
     * when the target exists).
     *
     * @param baseDir  base directory the result must be confined to
     * @param userPath untrusted relative path or file name
     * @return the normalized absolute path, or null if it is illegal or escapes baseDir
     */
    public static Path resolveInBase(String baseDir, String userPath) {
        if (baseDir == null || userPath == null || userPath.indexOf('\0') != -1) {
            return null;
        }
        try {
            Path base = Paths.get(baseDir).toAbsolutePath().normalize();
            Path resolved = base.resolve(userPath).normalize();
            if (!resolved.startsWith(base) || resolved.equals(base)) {
                return null;
            }
            if (Files.exists(resolved) && !resolved.toRealPath().startsWith(base.toRealPath())) {
                return null;
            }
            return resolved;
        } catch (InvalidPathException | IOException e) {
            logger.info("Illegal file path: " + e.toString());
            return null;
        }
    }


    public static String cmdFilter(String input) {
        if (input == null || !FILTER_PATTERN.matcher(input).matches()) {
            return null;
        }

        return input;
    }


    /**
     * Parse an untrusted command line into an argv array (no shell involved) restricted to an allowlist.
     * Commands in the first set take no arguments. Commands in the second set accept arguments
     * that satisfy {@link #cmdFilter(String)}.
     *
     * @param cmd untrusted command line
     * @return argv safe to pass to ProcessBuilder / Runtime.exec(String[]), or null if not allowed
     */
    public static String[] allowedCmdArgv(String cmd) {
        if (cmd == null) {
            return null;
        }
        String[] parts = cmd.trim().split("\\s+");
        if (parts.length > 8) {
            return null;
        }
        if (NO_ARG_COMMANDS.contains(parts[0])) {
            return parts.length == 1 ? parts : null;
        }
        if (!ARG_COMMANDS.contains(parts[0])) {
            return null;
        }
        for (int i = 1; i < parts.length; i++) {
            if (cmdFilter(parts[i]) == null) {
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

    /**
     * Remove CR, LF and NUL characters so the value is safe to use in an HTTP header (CWE-113).
     *
     * @param value untrusted header value, may be null
     * @return the value without CR/LF/NUL, or null if value is null
     */
    public static String cleanCRLF(String value) {
        if (value == null) {
            return null;
        }
        return value.replace("\r", "").replace("\n", "").replace("\0", "");
    }

    /**
     * Validate an untrusted redirect target. Only a same-origin relative path
     * (single leading slash) or an absolute http(s) url accepted by {@link #checkURL(String)}
     * is allowed. Control characters, whitespace and backslashes are rejected because
     * browsers normalize them and can turn a "relative" value into another origin.
     *
     * @param url untrusted redirect target
     * @return the url if it is safe to redirect to, otherwise null (fail closed)
     */
    public static String safeRedirectUrl(String url) {
        if (url == null || url.isEmpty()) {
            return null;
        }
        for (int i = 0; i < url.length(); i++) {
            char c = url.charAt(i);
            if (c <= ' ' || c == 0x7f || c == '\\') {
                return null;
            }
        }
        if (url.startsWith("/")) {
            return url.startsWith("//") ? null : url;
        }
        return checkURL(url);
    }

    public static void main(String[] args) {
    }

}