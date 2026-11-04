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
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.regex.Pattern;


public class SecurityUtil {

    private static final Pattern FILTER_PATTERN = Pattern.compile("^[a-zA-Z0-9_/\\.-]+$");
    private static final Set<String> COMMAND_ALLOWLIST = Collections.unmodifiableSet(
            new HashSet<String>(Arrays.asList("whoami", "id", "hostname", "pwd", "uname", "date", "ls")));
    private static final Set<String> LS_FLAG_ALLOWLIST = Collections.unmodifiableSet(
            new HashSet<String>(Arrays.asList("-l", "-a", "-h", "-la", "-al", "-lh", "-lah")));
    private static final Pattern PATH_ARG_PATTERN = Pattern.compile("^[a-zA-Z0-9_/.][a-zA-Z0-9_/.-]{0,254}$");
    private static final Pattern HOST_ARG_PATTERN =
            Pattern.compile("^[a-zA-Z0-9](?:[a-zA-Z0-9.-]{0,251}[a-zA-Z0-9])?(?::[0-9]{1,5})?$");
    private static final int MAX_ARGV = 8;
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
        if (url == null) {
            return "";
        }
        try {
            // java.net.URI is pure string parsing: no DNS lookup and no network I/O on the raw value.
            URI uri = new URI(url);
            String scheme = uri.getScheme();
            String host = uri.getHost();
            if (host == null || scheme == null
                    || !("http".equalsIgnoreCase(scheme) || "https".equalsIgnoreCase(scheme))) {
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


    public static String cmdFilter(String input) {
        if (!FILTER_PATTERN.matcher(input).matches()) {
            return null;
        }

        return input;
    }


    /**
     * Validate a single path argument for a process argv. Rejects (never sanitises) anything
     * that is null, too long, starts with '-' (would become a flag), contains ".." or has
     * characters outside <code>a-zA-Z0-9_/.-</code>.
     *
     * @param path path argument
     * @return the path unchanged if allowed, otherwise null
     */
    public static String safePathArg(String path) {
        if (path == null || path.contains("..")) {
            return null;
        }
        if (!PATH_ARG_PATTERN.matcher(path).matches()) {
            return null;
        }
        return path;
    }


    /**
     * Validate a host[:port] argument for a process argv. Rejects (never sanitises) anything
     * that is null, starts with '-', or is not a plain hostname / IPv4 literal with optional port.
     *
     * @param host host argument
     * @return the host unchanged if allowed, otherwise null
     */
    public static String safeHostArg(String host) {
        if (host == null) {
            return null;
        }
        if (!HOST_ARG_PATTERN.matcher(host).matches()) {
            return null;
        }
        return host;
    }


    /**
     * Return the allowlisted executable name equal to the given text, or null. The returned
     * value is the constant from the allowlist, never the caller supplied string.
     */
    private static String canonicalExecutable(String name) {
        for (String allowed : COMMAND_ALLOWLIST) {
            if (allowed.equals(name)) {
                return allowed;
            }
        }
        return null;
    }


    /**
     * Return the allowlisted ls flag equal to the given text, or null.
     */
    private static String canonicalLsFlag(String flag) {
        for (String allowed : LS_FLAG_ALLOWLIST) {
            if (allowed.equals(flag)) {
                return allowed;
            }
        }
        return null;
    }


    /**
     * Parse a command line into an argv array for use WITHOUT a shell.
     * The executable must be in COMMAND_ALLOWLIST and is taken from the allowlist constant,
     * not from the input. Only "ls" may take arguments: flags from LS_FLAG_ALLOWLIST, then
     * paths that pass {@link #safePathArg(String)}. Anything else is rejected.
     *
     * @param cmd command line
     * @return argv array, or null if the command is not allowed
     */
    public static String[] safeCommandArgv(String cmd) {
        if (cmd == null || cmd.trim().isEmpty()) {
            return null;
        }
        String[] parts = cmd.trim().split("\\s+");
        if (parts.length > MAX_ARGV) {
            return null;
        }
        String exe = canonicalExecutable(parts[0]);
        if (exe == null) {
            return null;
        }
        ArrayList<String> argv = new ArrayList<String>();
        argv.add(exe);
        if (parts.length > 1) {
            if (!"ls".equals(exe)) {
                return null;
            }
            int i = 1;
            while (i < parts.length && parts[i].startsWith("-")) {
                String flag = canonicalLsFlag(parts[i]);
                if (flag == null) {
                    return null;
                }
                argv.add(flag);
                i++;
            }
            argv.add("--");
            for (; i < parts.length; i++) {
                String path = safePathArg(parts[i]);
                if (path == null) {
                    return null;
                }
                argv.add(path);
            }
        }
        String[] result = argv.toArray(new String[argv.size()]);
        return isAllowedArgv(result) ? result : null;
    }


    /**
     * Re-validate a finished argv array right before it is handed to a process API.
     * Independent of how the array was produced, so call sites can enforce the policy locally.
     *
     * @param argv argv array
     * @return true only if the executable and every argument satisfy the allowlist policy
     */
    public static boolean isAllowedArgv(String[] argv) {
        if (argv == null || argv.length == 0 || argv.length > MAX_ARGV + 1) {
            return false;
        }
        String exe = canonicalExecutable(argv[0]);
        if (exe == null) {
            return false;
        }
        if (argv.length == 1) {
            return true;
        }
        if (!"ls".equals(exe)) {
            return false;
        }
        int i = 1;
        while (i < argv.length && canonicalLsFlag(argv[i]) != null) {
            i++;
        }
        if (i < argv.length && "--".equals(argv[i])) {
            i++;
        }
        for (; i < argv.length; i++) {
            if (safePathArg(argv[i]) == null) {
                return false;
            }
        }
        return true;
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