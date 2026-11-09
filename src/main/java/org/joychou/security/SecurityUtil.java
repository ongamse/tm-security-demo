package org.joychou.security;

import org.joychou.config.WebConfig;
import org.joychou.security.ssrf.SSRFChecker;
import org.joychou.security.ssrf.SocketHook;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.InetAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLDecoder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;


public class SecurityUtil {

    private static final Pattern FILTER_PATTERN = Pattern.compile("^[a-zA-Z0-9_/\\.-]+$");
    private static final Pattern ARG_PATTERN = Pattern.compile("^[a-zA-Z0-9_/\\.=:-]+$");
    private static final Pattern HEADER_CRLF_PATTERN = Pattern.compile("[\\r\\n]|%0[dD]|%0[aA]|%25(?=0[dDaA])");
    private static final Set<String> ALLOWED_COMMANDS = new HashSet<String>(
            Arrays.asList("whoami", "pwd", "date", "id", "uname", "hostname", "uptime", "ls", "echo"));
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
            String host = uri.getHost();
            // host is null for opaque / registry-based authorities; fail closed with an empty host
            return host == null ? "" : host.toLowerCase();
        } catch (URISyntaxException e) {
            return "";
        }
    }


    /**
     * Check that an outbound request URL is safe to fetch: strict http/https URI without user info,
     * and every address the host resolves to is public (not loopback, any-local, link-local such as
     * cloud metadata 169.254.169.254, site-local, unique-local IPv6, multicast or in the configured
     * block subnets). Callers must also disable redirect following (or re-validate each hop).
     *
     * @param url the url to check
     * @return true if safe, false otherwise (fail closed)
     */
    public static boolean isSafeOutboundUrl(String url) {
        return resolveSafeOutboundAddresses(url) != null;
    }


    /**
     * Validate an outbound request URL (see {@link #isSafeOutboundUrl(String)}) and resolve its host
     * exactly once. The returned addresses are the validated ones: callers must connect to these
     * addresses (pin them, e.g. through a custom DnsResolver) instead of resolving the host name a
     * second time, otherwise a DNS-rebinding answer can swap in an internal address between the check
     * and the connection.
     *
     * @param url the url to check
     * @return the validated public addresses of the url host, or null if the url is not safe (fail closed)
     */
    public static InetAddress[] resolveSafeOutboundAddresses(String url) {
        if (url == null || !isHttp(url)) {
            return null;
        }
        try {
            URI uri = new URI(url);
            if (uri.getUserInfo() != null) {
                return null;
            }
            return resolveSafeOutboundHost(uri.getHost());
        } catch (Exception e) {
            return null;
        }
    }


    /**
     * Check that a host only resolves to public addresses. See {@link #isSafeOutboundUrl(String)}.
     *
     * @param host host name or ip literal
     * @return true if safe, false otherwise (fail closed)
     */
    public static boolean isSafeOutboundHost(String host) {
        return resolveSafeOutboundHost(host) != null;
    }


    /**
     * Resolve a host once and return its addresses only if every one of them is public.
     *
     * @param host host name or ip literal
     * @return the validated addresses, or null if the host is not safe (fail closed)
     */
    public static InetAddress[] resolveSafeOutboundHost(String host) {
        if (host == null || host.isEmpty()) {
            return null;
        }
        try {
            InetAddress[] addrs = InetAddress.getAllByName(host);
            if (addrs.length == 0) {
                return null;
            }
            for (InetAddress addr : addrs) {
                if (addr.isAnyLocalAddress() || addr.isLoopbackAddress() || addr.isLinkLocalAddress()
                        || addr.isSiteLocalAddress() || addr.isMulticastAddress()) {
                    return null;
                }
                byte[] raw = addr.getAddress();
                if (raw.length == 16 && (raw[0] & 0xfe) == 0xfc) {
                    return null;  // IPv6 unique local fc00::/7
                }
                if (raw.length == 4 && SSRFChecker.isInternalIp(addr.getHostAddress())) {
                    return null;
                }
            }
            return addrs;
        } catch (Exception e) {
            return null;
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
     * Server-side allowlist of redirect destinations. The user supplied value is only a lookup key
     * (a short name, or the exact destination string); the redirect target that is returned always
     * comes from this fixed table, never from the request itself.
     */
    private static final Map<String, String> REDIRECT_TARGETS;

    static {
        Map<String, String> targets = new HashMap<String, String>();
        // same-origin paths
        targets.put("home", "/");
        targets.put("/", "/");
        targets.put("index", "/index");
        targets.put("/index", "/index");
        targets.put("login", "/login");
        targets.put("/login", "/login");
        targets.put("file-status", "/file/status");
        targets.put("/file/status", "/file/status");
        // trusted external destinations (keep in sync with resources/url/url_safe_domain.xml)
        targets.put("joychou-org", "https://www.joychou.org");
        targets.put("https://www.joychou.org", "https://www.joychou.org");
        targets.put("joychou-com", "https://www.joychou.com");
        targets.put("https://www.joychou.com", "https://www.joychou.com");
        targets.put("test-joychou-org", "https://test.joychou.org");
        targets.put("https://test.joychou.org", "https://test.joychou.org");
        REDIRECT_TARGETS = Collections.unmodifiableMap(targets);
    }


    /**
     * Resolve an untrusted redirect key to a trusted redirect destination. The key is looked up in a
     * fixed server-side allowlist ({@link #REDIRECT_TARGETS}); the returned string is the server-side
     * constant stored in that table, so no part of the request is ever used as the redirect target.
     * Unknown keys (javascript:, data:, //evil.com, /\evil.com, evil.com\@good.com ...) yield null.
     *
     * @param key untrusted redirect key supplied by the client
     * @return the allowlisted destination, otherwise null (callers must fail closed)
     */
    public static String resolveRedirectTarget(String key) {
        if (key == null) {
            return null;
        }
        return REDIRECT_TARGETS.get(key);
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
     * Parse a user supplied command line into an argv array without involving a shell.
     * The program must be on a fixed allowlist and every argument must match a strict
     * character allowlist (no shell metacharacters, quotes or whitespace).
     *
     * @param input user supplied command line, e.g. "ls -la /tmp"
     * @return argv array that can be passed to ProcessBuilder, or null if the command is not allowed
     */
    public static String[] parseAllowedCommand(String input) {
        if (input == null) {
            return null;
        }
        String trimmed = input.trim();
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

    /**
     * Neutralize a value before it is written into an HTTP response header, Location or Set-Cookie.
     * Removes raw CR/LF and their percent-encoded forms (<code>%0d</code>, <code>%0a</code>), repeating
     * until stable so that nested sequences such as <code>%250d</code> cannot reassemble into a line break.
     *
     * @param value untrusted header value
     * @return value without CR/LF sequences, or null when value is null
     */
    public static String sanitizeHeaderValue(String value) {
        if (value == null) {
            return null;
        }
        String previous;
        String current = value;
        do {
            previous = current;
            current = HEADER_CRLF_PATTERN.matcher(current).replaceAll("");
        } while (!current.equals(previous));
        return current;
    }

    /**
     * Validate a CORS Origin request header against the safe-domain allowlist (see {@link #checkURL}).
     * The Origin must be a bare http/https origin (scheme://host[:port]) with no user info, path,
     * query or fragment, otherwise it is rejected (fail closed).
     *
     * @param origin value of the Origin request header
     * @return the origin if it is allowlisted, null otherwise (including null/"null"/malformed values)
     */
    public static String checkCorsOrigin(String origin) {
        if (origin == null || checkURL(origin) == null) {
            return null;
        }
        try {
            URI uri = new URI(origin);
            if (uri.getUserInfo() != null || uri.getQuery() != null || uri.getFragment() != null) {
                return null;
            }
            String path = uri.getRawPath();
            if (path != null && !path.isEmpty()) {
                return null;
            }
            return origin;
        } catch (URISyntaxException e) {
            return null;
        }
    }

    /**
     * Emit CORS Allow-Origin / Allow-Credentials headers only for an allowlisted origin.
     *
     * @return true if the origin was allowlisted and headers were written
     */
    public static boolean applyCorsHeaders(String origin, javax.servlet.http.HttpServletResponse response) {
        String safeOrigin = checkCorsOrigin(origin);
        if (safeOrigin == null) {
            return false;
        }
        response.setHeader("Access-Control-Allow-Origin", sanitizeHeaderValue(safeOrigin));
        response.setHeader("Access-Control-Allow-Credentials", "true");
        response.addHeader("Vary", "Origin");
        return true;
    }

    public static void main(String[] args) {
    }

}