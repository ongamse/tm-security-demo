package org.joychou.security.ssrf;

import java.net.HttpURLConnection;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.net.util.SubnetUtils;
import org.joychou.config.WebConfig;
import org.joychou.security.SecurityUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public class SSRFChecker {

    private static final Logger logger = LoggerFactory.getLogger(SSRFChecker.class);
    private static String decimalIp;

    private static final String HOST_RE = "((?:[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?)|(?:\\[[0-9A-Fa-f:.]+\\]))";

    /** http(s)://host[:port][/path][?query][#fragment]; no userinfo, whitespace, backslash or control chars. */
    private static final Pattern HTTP_URL_PATTERN = Pattern.compile(
            "^(https?)://" + HOST_RE + "(:[0-9]{1,5})?(/[^?#\\s\\\\@]*)?(\\?[^#\\s\\\\]*)?(?:#\\S*)?$",
            Pattern.CASE_INSENSITIVE);

    /** jdbc:(postgresql|db2)://host[:port][/database]; nothing else. */
    private static final Pattern JDBC_URL_PATTERN = Pattern.compile(
            "^jdbc:(postgresql|db2)://" + HOST_RE + "(:[0-9]{1,5})?(/[A-Za-z0-9_.-]*)?$",
            Pattern.CASE_INSENSITIVE);

    private static final String ALNUM = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    /** Host is lower-cased before copying; ip6 literals use brackets, colon and hex digits. */
    private static final String HOST_ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789.-:[]";
    private static final String PORT_ALPHABET = ":0123456789";
    private static final String PATH_ALPHABET = ALNUM + "/%:!$&'()*+,;=~_.-";
    private static final String QUERY_ALPHABET = PATH_ALPHABET + "?@";
    private static final String DB_ALPHABET = ALNUM + "/_.-";

    public static boolean checkURLFckSSRF(String url) {
        if (null == url) {
            return false;
        }

        ArrayList<String> ssrfSafeDomains = WebConfig.getSsrfSafeDomains();
        try {
            String host = SecurityUtil.gethost(url);

            // 必须http/https
            if (!SecurityUtil.isHttp(url)) {
                return false;
            }

            if (ssrfSafeDomains.contains(host)) {
                return true;
            }
            for (String ssrfSafeDomain : ssrfSafeDomains) {
                if (host.endsWith("." + ssrfSafeDomain)) {
                    return true;
                }
            }
        } catch (Exception e) {
            logger.error(e.toString());
            return false;
        }
        return false;
    }

    /**
     * 解析url的ip，判断ip是否是内网ip，所以TTL设置为0的情况不适用。
     * url只允许https或者http，并且设置默认连接超时时间。
     * 该修复方案会主动请求重定向后的链接。
     *
     * @param url        check的url
     * @param checkTimes 设置重定向检测的最大次数，建议设置为10次
     * @return 安全返回true，危险返回false
     */
    public static boolean checkSSRF(String url, int checkTimes) {

        HttpURLConnection connection;
        int connectTime = 5 * 1000;  // 设置连接超时时间5s
        int i = 1;
        String finalUrl = url;
        try {
            do {
                // 判断当前请求的URL是否是内网ip
                if (isInternalIpByUrl(finalUrl)) {
                    logger.error("[-] SSRF check failed. Dangerous url: " + SecurityUtil.logSafe(finalUrl));
                    return false;  // 内网ip直接return，非内网ip继续判断是否有重定向
                }

                connection = (HttpURLConnection) requireSafeUri(finalUrl).toURL().openConnection();
                connection.setInstanceFollowRedirects(false);
                connection.setUseCaches(false); // 设置为false，手动处理跳转，可以拿到每个跳转的URL
                connection.setConnectTimeout(connectTime);
                //connection.setRequestMethod("GET");
                connection.connect(); // send dns request
                int responseCode = connection.getResponseCode(); // 发起网络请求
                if (responseCode >= 300 && responseCode <= 307 && responseCode != 304 && responseCode != 306) {
                    String redirectedUrl = connection.getHeaderField("Location");
                    if (null == redirectedUrl)
                        break;
                    finalUrl = redirectedUrl;
                    i += 1;  // 重定向次数加1
                    logger.info("redirected url: " + SecurityUtil.logSafe(finalUrl));
                    if (i == checkTimes) {
                        return false;
                    }
                } else
                    break;
            } while (connection.getResponseCode() != HttpURLConnection.HTTP_OK);
            connection.disconnect();
        } catch (SSRFException e) {
            logger.error(SecurityUtil.logSafe(e.getMessage()));
            return false;  // validation failure is never safe
        } catch (Exception e) {
            return true;  // 如果异常了，认为是安全的，防止是超时导致的异常而验证不成功。
        }
        return true; // 默认返回true
    }


    /**
     * Validate an untrusted http/https URL before a server side request is made.
     * The scheme must be http or https and every IP the host resolves to must be public.
     * Callers must request the returned URI (not the raw input) and must not follow redirects
     * automatically, otherwise a redirect can point back to an internal address.
     *
     * @param url untrusted url
     * @return the parsed, validated URI
     * @throws SSRFException if the url is malformed, not http/https or targets an internal address
     */
    public static URI requireSafeUri(String url) {
        if (StringUtils.isBlank(url)) {
            throw new SSRFException("[-] SSRF check failed. URL is empty");
        }
        Matcher m = HTTP_URL_PATTERN.matcher(url.trim());
        if (!m.matches()) {
            throw new SSRFException("[-] SSRF check failed. Only well formed http and https urls are allowed");
        }
        String scheme = "https".equalsIgnoreCase(m.group(1)) ? "https" : "http";
        String host = m.group(2).toLowerCase(Locale.ROOT);
        String port = m.group(3) == null ? "" : m.group(3);
        if (!port.isEmpty() && Integer.parseInt(port.substring(1)) > 65535) {
            throw new SSRFException("[-] SSRF check failed. Illegal port");
        }
        String path = m.group(4) == null ? "" : m.group(4);
        String query = m.group(5) == null ? "" : m.group(5);
        assertPublicHost(host.startsWith("[") ? host.substring(1, host.length() - 1) : host);

        // Re-serialise from the validated components, copying every character from a constant
        // alphabet; the raw request string is never used again and anything outside the
        // alphabet is rejected.
        String safeHost = copyFromAlphabet(host, HOST_ALPHABET);
        String safePort = copyFromAlphabet(port, PORT_ALPHABET);
        String safePath = copyFromAlphabet(path, PATH_ALPHABET);
        String safeQuery = copyFromAlphabet(query, QUERY_ALPHABET);
        URI uri;
        try {
            uri = new URI(scheme + "://" + safeHost + safePort + safePath + safeQuery);
        } catch (URISyntaxException e) {
            throw new SSRFException("[-] SSRF check failed. Illegal URL");
        }
        return uri;
    }


    /**
     * Validate an untrusted JDBC url of the form <code>jdbc:&lt;subprotocol&gt;://host[:port]/db</code>.
     * Only the given subprotocol is allowed, the host must be public, and driver properties
     * (query string / semicolon / colon properties) are rejected because they can load
     * attacker chosen classes or connect elsewhere.
     *
     * @param jdbcUrl     untrusted jdbc url
     * @param subprotocol expected subprotocol, such as postgresql or db2
     * @return the validated jdbc url
     * @throws SSRFException if the url is not acceptable
     */
    public static String requireSafeJdbcUrl(String jdbcUrl, String subprotocol) {
        if (jdbcUrl == null || !("postgresql".equals(subprotocol) || "db2".equals(subprotocol))) {
            throw new SSRFException("[-] SSRF check failed. Unsupported jdbc url");
        }
        // Only jdbc:<subprotocol>://host[:port][/db] is accepted. Query string, semicolon and colon
        // driver properties are rejected because they can load attacker chosen classes.
        Matcher m = JDBC_URL_PATTERN.matcher(jdbcUrl);
        if (!m.matches() || !subprotocol.equalsIgnoreCase(m.group(1))) {
            throw new SSRFException("[-] SSRF check failed. Unsupported jdbc url");
        }
        String host = m.group(2).toLowerCase(Locale.ROOT);
        String port = m.group(3) == null ? "" : m.group(3);
        if (!port.isEmpty() && Integer.parseInt(port.substring(1)) > 65535) {
            throw new SSRFException("[-] SSRF check failed. Illegal port");
        }
        String db = m.group(4) == null ? "" : m.group(4);
        assertPublicHost(host.startsWith("[") ? host.substring(1, host.length() - 1) : host);
        // The host must be on the configured allowlist (empty allowlist refuses everything) and the
        // allowlist entry itself, not the request value, is placed into the jdbc url.
        String allowedHost = null;
        for (String entry : WebConfig.getJdbcAllowedHosts()) {
            String candidate = entry == null ? "" : entry.trim().toLowerCase(Locale.ROOT);
            if (!candidate.isEmpty() && candidate.equals(host)) {
                allowedHost = copyFromAlphabet(candidate, HOST_ALPHABET);
                break;
            }
        }
        if (allowedHost == null) {
            throw new SSRFException("[-] SSRF check failed. Jdbc host is not allowed");
        }
        // Rebuild from the validated components, copying every character from a constant alphabet.
        String proto = "postgresql".equals(subprotocol) ? "postgresql" : "db2";
        return "jdbc:" + proto + "://" + allowedHost
                + copyFromAlphabet(port, PORT_ALPHABET) + copyFromAlphabet(db, DB_ALPHABET);
    }


    /**
     * Build a new string containing only characters taken from the constant alphabet.
     *
     * @throws SSRFException if the value contains a character that is not in the alphabet
     */
    private static String copyFromAlphabet(String value, String alphabet) {
        StringBuilder sb = new StringBuilder(value.length());
        for (int i = 0; i < value.length(); i++) {
            int idx = alphabet.indexOf(value.charAt(i));
            if (idx < 0) {
                throw new SSRFException("[-] SSRF check failed. Illegal character in url");
            }
            sb.append(alphabet.charAt(idx));
        }
        return sb.toString();
    }


    /**
     * Resolve the host and make sure none of the resolved addresses is internal.
     *
     * @param host host name or ip literal
     * @throws SSRFException if the host is empty, cannot be resolved or resolves to an internal address
     */
    public static void assertPublicHost(String host) {
        if (StringUtils.isEmpty(host)) {
            throw new SSRFException("[-] SSRF check failed. Host is empty");
        }
        try {
            // Octal ip such as 012.0.0.1 is converted first because of parser differences.
            if (isOctalIP(host) && isInternalIp(host2ip(host))) {
                throw new SSRFException("[-] SSRF check failed. Internal host: " + host);
            }
            for (InetAddress address : InetAddress.getAllByName(host)) {
                if (isInternalIp(address.getHostAddress())) {
                    throw new SSRFException("[-] SSRF check failed. Internal host: " + host);
                }
            }
        } catch (UnknownHostException e) {
            throw new SSRFException("[-] SSRF check failed. Unknown host: " + host);
        }
    }


    /**
     * 判断一个URL的IP是否是内网IP
     *
     * @return 如果是内网IP，返回true；非内网IP，返回false。
     */
    public static boolean isInternalIpByUrl(String url) {

        String host = url2host(url);
        if (host.equals("")) {
            return true; // 异常URL当成内网IP等非法URL处理
        }

        String ip = host2ip(host);
        if (ip.equals("")) {
            return true; // 如果域名转换为IP异常，则认为是非法URL
        }

        return isInternalIp(ip);
    }


    /**
     * 使用SubnetUtils库判断ip是否在内网网段
     *
     * @param strIP ip字符串
     * @return 如果是内网ip，返回true，否则返回false。
     */
    public static boolean isInternalIp(String strIP) {
        if (StringUtils.isEmpty(strIP)) {
            logger.error("[-] SSRF check failed. IP is empty. " + SecurityUtil.logSafe(strIP));
            return true;
        }

        // Loopback, any-local, link-local (incl. 169.254.169.254 metadata), site-local and multicast
        // addresses are never valid fetch targets. Also covers IPv6, which SubnetUtils cannot parse.
        InetAddress addr;
        try {
            addr = InetAddress.getByName(strIP);
        } catch (Exception e) {
            logger.error("[-] SSRF check failed. Illegal IP: " + SecurityUtil.logSafe(strIP));
            return true;
        }
        if (addr.isAnyLocalAddress() || addr.isLoopbackAddress() || addr.isLinkLocalAddress()
                || addr.isSiteLocalAddress() || addr.isMulticastAddress()) {
            logger.error("[-] SSRF check failed. Internal IP: " + SecurityUtil.logSafe(strIP));
            return true;
        }
        if (!(addr instanceof Inet4Address)) {
            // IPv6 unique local addresses fc00::/7
            return (addr.getAddress()[0] & 0xfe) == 0xfc;
        }

        ArrayList<String> blackSubnets = WebConfig.getSsrfBlockIps();
        for (String subnet : blackSubnets) {
            SubnetUtils utils = new SubnetUtils(subnet);
            if (utils.getInfo().isInRange(strIP)) {
                logger.error("[-] SSRF check failed. Internal IP: " + SecurityUtil.logSafe(strIP));
                return true;
            }
        }

        return false;

    }


    /**
     * Convert host to decimal ip.
     * Since there is a bypass in octal using {@link InetAddress#getHostAddress()},
     * the function of converting octal to decimal is added.
     * If it still can be bypassed, please submit
     * <a href="https://github.com/JoyChou93/java-sec-code/pulls">PullRequests</a> or
     * <a href="https://github.com/JoyChou93/java-sec-code/issues">Issues</a>.<br>
     *
     * <p>Normal:</p>
     * <ul>
     *    <li>69299689 to 10.23.78.233</li>
     *    <li>012.0x17.78.233 to 10.23.78.233 </li>
     *    <li>012.027.0116.0351 to 10.23.78.233</li>
     *    <li>127.0.0.1.xip.io to 127.0.0.1</li>
     *    <li>127.0.0.1.nip.io to 127.0.0.1</li>
     * </ul>

     * <p>Bypass: </p>
     * <ul>
     *     <li>01205647351 {@link InetAddress#getHostAddress()} result is 71.220.183.247, actually 10.23.78.233</li>
     *     <li>012.23.78.233 {@link InetAddress#getHostAddress()} result is 12.23.78.233, actually 10.23.78.233</li>
     *     <li>012.23.233 {@link InetAddress#getHostAddress()} result is  12.23.0.233, actually 10.23.0.233</li>
     *     <li>012.233 {@link InetAddress#getHostAddress()} result is 12.0.0.233, actually 10.0.0.233</li>
     * </ul>
     * @return decimal ip
     */
    public static String host2ip(String host) {

        if (null == host) {
            return "";
        }

         // convert octal to decimal
         if(isOctalIP(host)) {
             host = decimalIp;
         }

        try {
            // send dns request
            InetAddress IpAddress = InetAddress.getByName(host);
            return IpAddress.getHostAddress();
        } catch (Exception e) {
            logger.error("host2ip exception " + SecurityUtil.logSafe(e.getMessage()));
            return "";
        }
    }


    /**
     * Check whether the host is an octal IP, if so, convert it to decimal.
     * @return Octal ip returns true, others return false. 012.23.78.233 return true. 012.0x17.78.233 return false.
     */
    public static boolean isOctalIP(String host) {
        try{
            String[] ipParts = host.split("\\.");
            StringBuilder newDecimalIP = new StringBuilder();
            boolean is_octal = false;

            // Octal ip only has number and dot character.
            if (isNumberOrDot(host)) {

                // not support ipv6
                if (ipParts.length > 4) {
                    logger.error("Illegal ipv4: " + SecurityUtil.logSafe(host));
                    return false;
                }

                // 01205647351
                if( ipParts.length == 1 && host.startsWith("0") ) {
                    decimalIp = Integer.valueOf(host, 8).toString();
                    return true;
                }

                // 012.23.78.233
                for(String ip : ipParts) {
                    if (!isNumber(ip)){
                        logger.error("Illegal ipv4: " + SecurityUtil.logSafe(host));
                        return false;
                    }
                    // start with "0", but not "0"
                    if (ip.startsWith("0") && !ip.equals("0")) {
                        if (Integer.valueOf(ip, 8) >= 256){
                            logger.error("Illegal ipv4: " + SecurityUtil.logSafe(host));
                            return false;
                        }
                        newDecimalIP.append(Integer.valueOf(ip, 8)).append(".");
                        is_octal = true;
                    }else{
                        if (Integer.valueOf(ip, 10) >= 256) {
                            logger.error("Illegal ipv4: " + SecurityUtil.logSafe(host));
                            return false;
                        }
                        newDecimalIP.append(ip).append(".");
                    }
                }
                // delete last char .
                decimalIp = newDecimalIP.substring(0, newDecimalIP.lastIndexOf("."));
            }
            return is_octal;
        } catch (Exception e){
            logger.error("SSRFChecker isOctalIP exception: " + SecurityUtil.logSafe(e.getMessage()));
            return false;
        }

    }

    /**
     * Check string is a number.
     * @return If string is a number 0-9, return true. Otherwise, return false.
     */
    private static boolean isNumber(String str) {
        if (null == str || "".equals(str)) {
            return false;
        }
        for (int i = 0; i < str.length(); i++) {
            char ch = str.charAt(i);
            if (ch < '0' || ch > '9') {
                return false;
            }
        }
        return true;
    }


    /**
     * Check string is a number or dot.
     * @return If string is a number or a dot, return true. Otherwise, return false.
     */
    private static boolean isNumberOrDot(String s) {
        for (int i = 0; i < s.length(); i++) {
            char ch = s.charAt(i);
            if ((ch < '0' || ch > '9') && ch != '.'){
                return false;
            }
        }
        return true;
    }

    /**
     * Get host from URL which the protocol must be http:// or https:// and not be //.
     */
    private static String url2host(String url) {
        if (url == null) {
            return "";
        }
        Matcher m = HTTP_URL_PATTERN.matcher(url.trim());
        if (!m.matches()) {
            return "";
        }
        String host = m.group(2).toLowerCase(Locale.ROOT);
        return host.startsWith("[") ? host.substring(1, host.length() - 1) : host;
    }

}
