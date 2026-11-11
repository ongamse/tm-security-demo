package org.joychou.security;

import org.joychou.config.WebConfig;
import org.joychou.security.ssrf.SSRFChecker;
import org.joychou.security.ssrf.SocketHook;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;


public class SecurityUtil {

    private static final Pattern FILTER_PATTERN = Pattern.compile("^[a-zA-Z0-9_/\\.-]+$");
    /**
     * Closed set of commands that may be executed on behalf of a request. Callers compare the request
     * value against these entries and execute the matching constant entry, never the request string.
     */
    public static final List<String[]> ALLOWED_CMDS = Collections.unmodifiableList(Arrays.asList(
            new String[]{"whoami"},
            new String[]{"id"},
            new String[]{"date"},
            new String[]{"uname"},
            new String[]{"hostname"},
            new String[]{"pwd"},
            new String[]{"ls"}));
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


    private static final String HOST_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-";
    private static final String IPV6_CHARS = "0123456789abcdefABCDEF:.";
    private static final String DIGIT_CHARS = "0123456789";
    private static final String HEX_CHARS = "0123456789abcdefABCDEF";
    private static final String HEX_UPPER = "0123456789ABCDEF";
    private static final String DB_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-.";
    private static final String PATH_CHARS =
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~!$&'()*+,;=:@/?";


    /**
     * Rebuild a string from a closed alphabet. Every character of the result is the alphabet's own
     * constant character, never the untrusted one; any character outside the alphabet rejects the input.
     *
     * @return the rebuilt string, or null if input is null or contains a character outside the alphabet
     */
    private static String constantChars(String input, String alphabet) {
        if (input == null) {
            return null;
        }
        StringBuilder sb = new StringBuilder(input.length());
        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            boolean found = false;
            for (int j = 0; j < alphabet.length(); j++) {
                if (alphabet.charAt(j) == c) {
                    sb.append(alphabet.charAt(j));
                    found = true;
                    break;
                }
            }
            if (!found) {
                return null;
            }
        }
        return sb.toString();
    }


    private static final String TOKEN_CHARS =
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.@-";

    /**
     * Rebuild a short identifier (e.g. a username) from a constant alphabet. The result is made only of the
     * alphabet's own characters; any other character rejects the input.
     *
     * @param input untrusted identifier
     * @return rebuilt identifier (1 to 64 characters), or null if input is null, empty, too long or has
     * characters outside the alphabet
     */
    public static String safeToken(String input) {
        if (input == null || input.isEmpty() || input.length() > 64) {
            return null;
        }
        return constantChars(input, TOKEN_CHARS);
    }


    /**
     * Parse a decimal tcp port without using the untrusted characters as the result.
     *
     * @return 0..65535, or -1 if the input is empty, too long, not all digits or out of range
     */
    private static int constantPort(String input) {
        if (input == null || input.isEmpty() || input.length() > 5) {
            return -1;
        }
        int port = 0;
        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            int digit = -1;
            for (int j = 0; j < DIGIT_CHARS.length(); j++) {
                if (DIGIT_CHARS.charAt(j) == c) {
                    digit = j;
                    break;
                }
            }
            if (digit < 0) {
                return -1;
            }
            port = port * 10 + digit;
        }
        return port > 65535 ? -1 : port;
    }


    /**
     * Split <code>host[:port]</code> / <code>[ipv6][:port]</code> into a canonical host (lower case, built
     * from {@link #HOST_CHARS} / {@link #IPV6_CHARS}) and a canonical port ("" when absent).
     *
     * @return {host, port}, or null if the authority is malformed
     */
    private static String[] splitHostPort(String authority) {
        if (authority == null || authority.isEmpty()) {
            return null;
        }
        String host;
        String portPart = "";
        if (authority.charAt(0) == '[') {
            int close = authority.indexOf(']');
            if (close < 0) {
                return null;
            }
            String inner = constantChars(authority.substring(1, close), IPV6_CHARS);
            if (inner == null || inner.isEmpty()) {
                return null;
            }
            String after = authority.substring(close + 1);
            if (!after.isEmpty()) {
                if (after.charAt(0) != ':') {
                    return null;
                }
                portPart = after.substring(1);
            }
            host = "[" + inner.toLowerCase(Locale.ROOT) + "]";
        } else {
            String hostPart = authority;
            int colon = authority.indexOf(':');
            if (colon >= 0) {
                hostPart = authority.substring(0, colon);
                portPart = authority.substring(colon + 1);
            }
            String mapped = constantChars(hostPart, HOST_CHARS);
            if (mapped == null || mapped.isEmpty()) {
                return null;
            }
            host = mapped.toLowerCase(Locale.ROOT);
        }
        String port = "";
        if (!portPart.isEmpty()) {
            int p = constantPort(portPart);
            if (p < 0) {
                return null;
            }
            port = Integer.toString(p);
        }
        return new String[]{host, port};
    }


    /**
     * Index of the end of the authority component that starts at <code>start</code>.
     */
    private static int authorityEnd(String s, int start) {
        int end = start;
        while (end < s.length()) {
            char c = s.charAt(end);
            if (c == '/' || c == '?' || c == '#') {
                break;
            }
            end++;
        }
        return end;
    }


    /**
     * Get http url host. The url is parsed by hand (no URL/URI object is built from the untrusted string).
     *
     * @param url url
     * @return host (lower case), or empty string if the url is malformed or has no host
     */
    public static String gethost(String url) {
        if (url == null) {
            return "";
        }
        int sep = url.indexOf("://");
        if (sep <= 0) {
            return "";
        }
        if (constantChars(url.substring(0, sep), "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+-.") == null) {
            return "";
        }
        int start = sep + 3;
        String authority = url.substring(start, authorityEnd(url, start));
        int at = authority.indexOf('@');
        if (at >= 0) {
            if (authority.indexOf('@', at + 1) >= 0) {
                return "";
            }
            authority = authority.substring(at + 1);
        }
        String[] hostPort = splitHostPort(authority);
        return hostPort == null ? "" : hostPort[0];
    }


    /**
     * Rebuild an untrusted http(s) url from validated components: the scheme is a constant, the host and
     * port are re-emitted from a closed alphabet / parsed integer, user info is rejected, the fragment is
     * dropped and path/query characters are re-emitted from a closed alphabet or percent-encoded. The
     * returned value is what should be requested, so the host that was checked is the host that is fetched.
     *
     * @param url untrusted url
     * @return canonical http(s) url, or null if the url is not an acceptable http(s) url
     */
    public static String canonicalHttpUrl(String url) {
        if (url == null) {
            return null;
        }
        String scheme;
        int start;
        if (url.startsWith("https://")) {
            scheme = "https";
            start = 8;
        } else if (url.startsWith("http://")) {
            scheme = "http";
            start = 7;
        } else {
            return null;
        }
        int end = authorityEnd(url, start);
        String[] hostPort = splitHostPort(url.substring(start, end));
        if (hostPort == null) {
            return null;
        }
        StringBuilder sb = new StringBuilder();
        sb.append(scheme).append("://").append(hostPort[0]);
        if (!hostPort[1].isEmpty()) {
            sb.append(':').append(hostPort[1]);
        }
        String tail = url.substring(end);
        if (tail.isEmpty() || tail.charAt(0) == '?' || tail.charAt(0) == '#') {
            sb.append('/');
        }
        int i = 0;
        while (i < tail.length()) {
            int cp = tail.codePointAt(i);
            i += Character.charCount(cp);
            if (cp == '#') {
                break;
            }
            if (cp == '%') {
                String hex = i + 2 <= tail.length() ? constantChars(tail.substring(i, i + 2), HEX_CHARS) : null;
                if (hex != null) {
                    sb.append('%').append(hex);
                    i += 2;
                } else {
                    sb.append("%25");
                }
                continue;
            }
            String plain = cp < 128 ? constantChars(String.valueOf((char) cp), PATH_CHARS) : null;
            if (plain != null) {
                sb.append(plain);
                continue;
            }
            byte[] bytes = new String(Character.toChars(cp)).getBytes(StandardCharsets.UTF_8);
            for (byte b : bytes) {
                sb.append('%').append(HEX_UPPER.charAt((b >> 4) & 0xF)).append(HEX_UPPER.charAt(b & 0xF));
            }
        }
        return sb.toString();
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
     * Validate an untrusted JDBC url ({@link #checkJdbcUrl(String, String)}) and rebuild it from validated
     * components: the prefix is the caller's constant, host / db name are re-emitted from closed alphabets
     * and the port from a parsed integer. The returned value, not the request string, is what must be
     * passed to DriverManager.
     *
     * @param jdbcUrl untrusted jdbc url
     * @param prefix  required prefix, e.g. <code>jdbc:postgresql://</code>
     * @return the rebuilt jdbc url, or null if the url is not allowed
     */
    public static String safeJdbcUrl(String jdbcUrl, String prefix) {
        if (!checkJdbcUrl(jdbcUrl, prefix)) {
            return null;
        }
        String[] parts = jdbcUrl.substring(prefix.length()).split("/", 2);
        String[] hostPort = splitHostPort(parts[0]);
        if (hostPort == null || hostPort[0].startsWith("[")) {
            return null;
        }
        StringBuilder sb = new StringBuilder(prefix);
        sb.append(hostPort[0]);
        if (!hostPort[1].isEmpty()) {
            sb.append(':').append(hostPort[1]);
        }
        if (parts.length > 1) {
            String db = constantChars(parts[1], DB_CHARS);
            if (db == null) {
                return null;
            }
            sb.append('/').append(db);
        }
        return sb.toString();
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
            try {
                if (!resolved.toRealPath().startsWith(base.toRealPath())) {
                    return null;
                }
            } catch (NoSuchFileException e) {
                // Target does not exist yet: lexical confinement above is sufficient.
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
     * Closed set of directories that may be listed on behalf of a request.
     */
    public static final List<String> ALLOWED_DIRS = Collections.unmodifiableList(
            Arrays.asList("/tmp", "/var/tmp", "."));

    /**
     * Closed set of hosts that may be fetched on behalf of a request.
     */
    public static final List<String> ALLOWED_HOSTS = Collections.unmodifiableList(
            Arrays.asList("localhost", "localhost:8080", "127.0.0.1", "127.0.0.1:8080"));

    /**
     * Look an untrusted value up in a closed set and return the matching constant entry.
     * The returned string is the allowlist's own literal, never the untrusted input.
     *
     * @param input   untrusted value
     * @param allowed closed set of constants
     * @return the matching constant, or null if input is not in the set
     */
    public static String allowedConstant(String input, List<String> allowed) {
        if (input == null) {
            return null;
        }
        for (String candidate : allowed) {
            if (candidate.equals(input)) {
                return candidate;
            }
        }
        return null;
    }

    /**
     * Map an untrusted command name onto a constant argv from {@link #ALLOWED_CMDS}.
     * Only exact, argument-less matches are accepted; the returned array is a copy of the constant
     * entry, never built from the untrusted input.
     *
     * @param cmd untrusted command
     * @return constant argv safe to pass to ProcessBuilder / Runtime.exec(String[]), or null if not allowed
     */
    public static String[] allowedCmdArgv(String cmd) {
        if (cmd == null) {
            return null;
        }
        String trimmed = cmd.trim();
        for (String[] candidate : ALLOWED_CMDS) {
            if (candidate[0].equals(trimmed)) {
                return candidate.clone();
            }
        }
        return null;
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

    /**
     * Closed set of same-origin paths that may be redirected to on behalf of a request.
     */
    public static final List<String> REDIRECT_PATHS = Collections.unmodifiableList(
            Arrays.asList("/", "/urlRedirect/test"));

    /**
     * Closed map of allowed redirect host -> hard-coded absolute redirect url. More specific hosts come first.
     */
    private static final Map<String, String> REDIRECT_HOSTS;

    static {
        Map<String, String> hosts = new LinkedHashMap<>();
        hosts.put("test.joychou.org", "https://test.joychou.org/");
        hosts.put("joychou.org", "https://www.joychou.org/");
        hosts.put("joychou.com", "https://www.joychou.com/");
        hosts.put("localhost", "http://localhost:8080/");
        REDIRECT_HOSTS = Collections.unmodifiableMap(hosts);
    }

    /**
     * Map an untrusted redirect request onto a constant redirect target. The request value is only used to
     * select an entry (exact path match, or host match after {@link #safeRedirectUrl(String)}); the returned
     * string is always the allowlist's own literal, never the request value or something built from it.
     *
     * @param url untrusted redirect target
     * @return constant redirect target, or null if not allowed (fail closed)
     */
    public static String allowedRedirectTarget(String url) {
        String safe = safeRedirectUrl(url);
        if (safe == null) {
            return null;
        }
        for (String candidate : REDIRECT_PATHS) {
            if (candidate.equals(safe)) {
                return candidate;
            }
        }
        String host = gethost(safe);
        if (host.isEmpty()) {
            return null;
        }
        for (Map.Entry<String, String> entry : REDIRECT_HOSTS.entrySet()) {
            String allowedHost = entry.getKey();
            if (host.equals(allowedHost) || host.endsWith("." + allowedHost)) {
                return entry.getValue();
            }
        }
        return null;
    }

    /**
     * Closed set of origins that may be granted CORS access.
     */
    public static final List<String> ALLOWED_ORIGINS = Collections.unmodifiableList(Arrays.asList(
            "https://joychou.com", "https://www.joychou.com",
            "https://joychou.org", "https://www.joychou.org",
            "https://test.joychou.org",
            "http://localhost", "http://localhost:8080"));

    /**
     * Map an untrusted Origin header onto the allowlist's own constant string. The request value is only
     * compared with {@link #ALLOWED_ORIGINS}; the returned value is the matching list element.
     *
     * @param origin untrusted Origin header value, may be null
     * @return the matching constant origin, or null if not allowed (emit no CORS header)
     */
    public static String allowedOrigin(String origin) {
        if (origin == null) {
            return null;
        }
        for (String candidate : ALLOWED_ORIGINS) {
            if (candidate.equals(origin)) {
                return candidate;
            }
        }
        return null;
    }

    /**
     * Closed set of values that may be reflected into the demo CRLF response headers.
     */
    public static final List<String> ALLOWED_HEADER_VALUES = Collections.unmodifiableList(
            Arrays.asList("test", "value1", "value2", "joychou"));

    private static final String FILENAME_CHARS =
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-";

    /**
     * Build a download file name from the closed alphabet {@link #FILENAME_CHARS}: every output character is
     * the alphabet's own constant, characters outside it (CR, LF, quotes, separators, non-ASCII) become '_'.
     *
     * @param name untrusted file name, may be null
     * @return a header-safe file name, "download" if the input is null or empty
     */
    public static String headerSafeFileName(String name) {
        if (name == null || name.isEmpty()) {
            return "download";
        }
        StringBuilder sb = new StringBuilder(name.length());
        for (int i = 0; i < name.length(); i++) {
            char c = name.charAt(i);
            char out = '_';
            for (int j = 0; j < FILENAME_CHARS.length(); j++) {
                if (FILENAME_CHARS.charAt(j) == c) {
                    out = FILENAME_CHARS.charAt(j);
                    break;
                }
            }
            sb.append(out);
        }
        return sb.toString();
    }

    public static void main(String[] args) {
    }

}