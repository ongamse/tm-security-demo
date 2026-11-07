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
import java.net.URL;
import java.net.URLDecoder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
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
     * Validate a user supplied url before the server makes an outbound request to it.
     * The scheme must be http/https, the host must be consistent between the URI and URL parsers,
     * and every address the host resolves to must be public (no loopback, link-local/metadata,
     * private or configured blocked ranges). Callers must also disable redirects.
     *
     * @param url The url that needs to check.
     * @return Safe url returns true. Dangerous url returns false.
     */
    public static boolean checkOutboundUrl(String url) {
        if (url == null) {
            return false;
        }
        try {
            URI uri = new URI(url);
            String scheme = uri.getScheme();
            if (scheme == null || !("http".equalsIgnoreCase(scheme) || "https".equalsIgnoreCase(scheme))) {
                return false;
            }
            String host = uri.getHost();
            if (host == null || host.isEmpty()) {
                return false;
            }
            // reject parser differentials between java.net.URI and java.net.URL
            String urlHost = new URL(url).getHost();
            if (urlHost == null || !urlHost.equalsIgnoreCase(host)) {
                return false;
            }
            return !SSRFChecker.isInternalIpByUrl(url);
        } catch (Exception e) {
            logger.error(e.toString());
            return false;
        }
    }


    /**
     * Validate a request derived value before it is written into an HTTP response header.
     * Any ASCII control character (CR, LF, NUL, ...) except horizontal tab, and DEL, is rejected
     * so that the value cannot split the response (CWE-113).
     *
     * @param value candidate header value
     * @return the original value when it is safe; null when it is null or contains control characters
     */
    public static String safeHeaderValue(String value) {
        if (value == null) {
            return null;
        }
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if ((c < 0x20 && c != '\t') || c == 0x7f) {
                return null;
            }
        }
        return value;
    }


    /**
     * Validate a user supplied redirect target (CWE-601). Fails closed.
     * Accepted targets are either a same-origin relative path (single leading slash, no
     * "//" or backslash tricks) or an absolute http/https url whose host is allowed by
     * {@link #checkURL(String)}, has no userinfo, and is parsed identically by java.net.URI and
     * java.net.URL. Any control character (CR, LF, ...) is rejected.
     *
     * @param url candidate redirect target
     * @return the original url when safe; null otherwise
     */
    public static String safeRedirectUrl(String url) {
        if (url == null || safeHeaderValue(url) == null || url.indexOf('\\') >= 0) {
            return null;
        }
        if (url.startsWith("/")) {
            // same-origin path only; "//host" is a scheme-relative url
            if (url.startsWith("//")) {
                return null;
            }
            try {
                URI uri = new URI(url);
                if (uri.getScheme() != null || uri.getRawAuthority() != null) {
                    return null;
                }
            } catch (URISyntaxException e) {
                return null;
            }
            return url;
        }
        if (checkURL(url) == null) {
            return null;
        }
        try {
            URI uri = new URI(url);
            String host = uri.getHost();
            if (host == null || uri.getRawUserInfo() != null) {
                return null;
            }
            String urlHost = new URL(url).getHost();
            if (urlHost == null || !urlHost.equalsIgnoreCase(host)) {
                return null;
            }
        } catch (Exception e) {
            return null;
        }
        return url;
    }


    private static final Pattern JDBC_HOST_PATTERN = Pattern.compile(
            "^([A-Za-z0-9.-]+|\\[[0-9A-Fa-f:.]+\\])(:[0-9]{1,5})?$");
    private static final Pattern JDBC_DB_PATTERN = Pattern.compile("^[A-Za-z0-9_.-]*$");
    private static final Set<String> POSTGRESQL_JDBC_PARAMS = new HashSet<>(Arrays.asList(
            "user", "password", "ssl", "sslmode", "connectTimeout", "loginTimeout",
            "socketTimeout", "ApplicationName", "currentSchema"));
    private static final Set<String> DB2_JDBC_PARAMS = new HashSet<>(Arrays.asList(
            "user", "password", "sslConnection", "loginTimeout", "connectionTimeout", "currentSchema"));

    /**
     * Check the host:port authority of a jdbc url against the SSRF rules.
     */
    private static boolean checkJdbcAuthority(String authority) {
        return JDBC_HOST_PATTERN.matcher(authority).matches()
                && checkOutboundUrl("http://" + authority + "/");
    }

    /**
     * Allowlist check for <code>jdbc:postgresql://host[:port]/db[?key=value&amp;...]</code>.
     * The host must be public and only plain connection parameters are allowed, so that parameters
     * which load classes (socketFactory, sslfactory, authenticationPluginClassName, ...) are rejected.
     */
    public static boolean checkPostgresqlJdbcUrl(String jdbcUrl) {
        String prefix = "jdbc:postgresql://";
        if (jdbcUrl == null || !jdbcUrl.startsWith(prefix)) {
            return false;
        }
        String rest = jdbcUrl.substring(prefix.length());
        String query = "";
        int q = rest.indexOf('?');
        if (q >= 0) {
            query = rest.substring(q + 1);
            rest = rest.substring(0, q);
        }
        int slash = rest.indexOf('/');
        if (slash < 0) {
            return false;
        }
        if (!checkJdbcAuthority(rest.substring(0, slash))
                || !JDBC_DB_PATTERN.matcher(rest.substring(slash + 1)).matches()) {
            return false;
        }
        if (!query.isEmpty()) {
            for (String pair : query.split("&", -1)) {
                int eq = pair.indexOf('=');
                String key = eq < 0 ? pair : pair.substring(0, eq);
                if (!POSTGRESQL_JDBC_PARAMS.contains(key)) {
                    return false;
                }
            }
        }
        return true;
    }

    /**
     * Allowlist check for <code>jdbc:db2://host[:port]/db[:key=value;...;]</code>.
     * The host must be public and only plain connection properties are allowed.
     */
    public static boolean checkDb2JdbcUrl(String jdbcUrl) {
        String prefix = "jdbc:db2://";
        if (jdbcUrl == null || !jdbcUrl.startsWith(prefix)) {
            return false;
        }
        String rest = jdbcUrl.substring(prefix.length());
        int slash = rest.indexOf('/');
        if (slash < 0) {
            return false;
        }
        String authority = rest.substring(0, slash);
        String dbAndProps = rest.substring(slash + 1);
        String props = "";
        int colon = dbAndProps.indexOf(':');
        if (colon >= 0) {
            props = dbAndProps.substring(colon + 1);
            dbAndProps = dbAndProps.substring(0, colon);
        }
        if (!checkJdbcAuthority(authority) || !JDBC_DB_PATTERN.matcher(dbAndProps).matches()) {
            return false;
        }
        if (!props.isEmpty()) {
            for (String pair : props.split(";", -1)) {
                if (pair.isEmpty()) {
                    continue; // trailing ';'
                }
                int eq = pair.indexOf('=');
                String key = eq < 0 ? pair : pair.substring(0, eq);
                if (!DB2_JDBC_PARAMS.contains(key)) {
                    return false;
                }
            }
        }
        return true;
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
     * Commands that may be run through the command execution endpoints.
     */
    private static final Set<String> ALLOWED_COMMANDS = new HashSet<>(
            Arrays.asList("whoami", "date", "hostname", "uname", "id", "pwd", "ls"));

    /**
     * Split a user supplied command line into an argv array without involving a shell.
     * The executable must be in the allowlist and every argument must match the
     * safe character pattern (see {@link #cmdFilter(String)}).
     *
     * @param cmdLine command line supplied by the user
     * @return argv array, or null if the command is not allowed
     */
    public static String[] safeCommand(String cmdLine) {
        if (cmdLine == null) {
            return null;
        }
        String trimmed = cmdLine.trim();
        if (trimmed.isEmpty()) {
            return null;
        }
        String[] argv = trimmed.split("\\s+");
        if (!ALLOWED_COMMANDS.contains(argv[0])) {
            return null;
        }
        for (int i = 1; i < argv.length; i++) {
            if (cmdFilter(argv[i]) == null) {
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