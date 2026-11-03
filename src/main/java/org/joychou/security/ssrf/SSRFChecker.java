package org.joychou.security.ssrf;

import java.net.HttpURLConnection;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.URL;
import java.util.ArrayList;
import java.util.regex.Pattern;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.net.util.SubnetUtils;
import org.joychou.config.WebConfig;
import org.joychou.security.SecurityUtil;
import org.joychou.util.WebUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public class SSRFChecker {

    private static final Logger logger = LoggerFactory.getLogger(SSRFChecker.class);
    private static String decimalIp;

    // Hosts made only of decimal / hex numbers and dots (e.g. 2130706433, 0x7f.1, 017700000001).
    private static final Pattern NUMERIC_HOST =
            Pattern.compile("^(0[xX][0-9a-fA-F]+|[0-9]+)(\\.(0[xX][0-9a-fA-F]+|[0-9]+))*$");
    // Canonical dotted-quad IPv4 without leading zeros.
    private static final Pattern DOTTED_QUAD = Pattern.compile(
            "^(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(\\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])){3}$");

    /**
     * Central outbound-URL validation. The URL must be a http/https URL without user info and
     * its host must not be (or resolve to) a loopback, link-local, private, metadata or other
     * non-public address. Every resolved address is checked, not only the first one.
     * Callers must also disable automatic redirects (or re-validate every hop).
     *
     * @param url the url that is about to be requested
     * @return true if the url may be requested, false otherwise (fails closed)
     */
    public static boolean isSafeOutboundUrl(String url) {
        return canonicalOutboundUrl(url) != null;
    }

    /**
     * The single central outbound-URL validator. The input is strictly parsed
     * ({@link SecurityUtil#parseHttpUrl(String)}: http/https only, no user info, no backslash,
     * no control characters), the host must only resolve to public addresses, and the url that
     * is returned is re-constructed from the validated scheme / host / port / path / query.
     * Callers must request only the returned value (never the raw input) and must disable
     * automatic redirects (or re-validate every hop). This method only parses and resolves
     * names; it never connects.
     *
     * @param url the url that is about to be requested
     * @return the canonical url, or null when the url must not be requested (fails closed)
     */
    public static String canonicalOutboundUrl(String url) {
        SecurityUtil.HttpUrl parsed = SecurityUtil.parseHttpUrl(url);
        if (parsed == null) {
            return null;
        }
        // the host must be an exact member of the server-side allowlist and resolve to public
        // addresses only; the host used below is the allowlist's own entry, never the request text
        String allowedHost = allowlistedOutboundHost(parsed.getHost());
        if (allowedHost == null) {
            return null;
        }
        int port = parsed.getPort();
        if (port != -1 && (port < 1 || port > 65535)) {
            return null;
        }
        // scheme: server constant; path / query: re-built character by character from server-side alphabets
        String path = WebUtils.rebuildFromAllowed(parsed.getPath(), OUTBOUND_PATH_CHARS);
        if (path == null) {
            return null;
        }
        StringBuilder sb = new StringBuilder();
        sb.append("https".equals(parsed.getScheme()) ? "https" : "http").append("://").append(allowedHost);
        if (port != -1) {
            sb.append(':').append(port);
        }
        sb.append(path);
        if (parsed.getQuery() != null) {
            String query = WebUtils.rebuildFromAllowed(parsed.getQuery(), OUTBOUND_QUERY_CHARS);
            if (query == null) {
                return null;
            }
            sb.append('?').append(query);
        }
        return sb.toString();
    }

    // Server-side alphabets (RFC 3986 pchar subset, no backslash / whitespace / control characters).
    private static final String OUTBOUND_PATH_CHARS =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._~!$&'()*+,;=:@%/-";
    private static final String OUTBOUND_QUERY_CHARS = OUTBOUND_PATH_CHARS + "?";

    /**
     * Server-side outbound allowlist lookup. The host must equal (case-insensitively) an entry of
     * the configured safe domains (url_safe_domain.xml or ssrf_safe_domain.xml) and that entry must
     * only resolve to public addresses.
     *
     * @param host host taken from a request url
     * @return the allowlist's own entry (never the request string), or null (fails closed)
     */
    public static String allowlistedOutboundHost(String host) {
        if (host == null || host.isEmpty()) {
            return null;
        }
        ArrayList<String> allowed = new ArrayList<>();
        if (WebConfig.getSafeDomains() != null) {
            allowed.addAll(WebConfig.getSafeDomains());
        }
        if (WebConfig.getSsrfSafeDomains() != null) {
            allowed.addAll(WebConfig.getSsrfSafeDomains());
        }
        for (String entry : allowed) {
            if (entry != null && entry.equalsIgnoreCase(host)) {
                return isSafeOutboundHost(entry) ? entry : null;
            }
        }
        return null;
    }

    /**
     * Check that a host name or ip literal only resolves to public addresses.
     *
     * @param host host name, IPv4 literal or bracketed IPv6 literal
     * @return true if every resolved address is public, false otherwise (fails closed)
     */
    public static boolean isSafeOutboundHost(String host) {
        if (host == null || host.isEmpty()) {
            return false;
        }
        try {
            // Reject octal / hex / decimal-integer IPv4 notations that resolvers parse differently.
            if (NUMERIC_HOST.matcher(host).matches() && !DOTTED_QUAD.matcher(host).matches()) {
                return false;
            }
            InetAddress[] addresses = InetAddress.getAllByName(host);
            if (addresses.length == 0) {
                return false;
            }
            for (InetAddress address : addresses) {
                if (isBlockedAddress(address)) {
                    logger.error("[-] SSRF check failed. Internal IP: " + WebUtils.sanitizeLog(address.getHostAddress()));
                    return false;
                }
            }
            return true;
        } catch (Exception e) {
            logger.error("isSafeOutboundHost exception: " + WebUtils.sanitizeLog(e.getMessage()));
            return false;
        }
    }

    private static boolean isBlockedAddress(InetAddress address) {
        if (address.isAnyLocalAddress() || address.isLoopbackAddress() || address.isLinkLocalAddress()
                || address.isSiteLocalAddress() || address.isMulticastAddress()) {
            return true;
        }
        byte[] b = address.getAddress();
        if (address instanceof Inet4Address) {
            int b0 = b[0] & 0xff;
            int b1 = b[1] & 0xff;
            int b2 = b[2] & 0xff;
            if (b0 == 0                                   // 0.0.0.0/8
                    || (b0 == 100 && (b1 & 0xc0) == 64)   // 100.64.0.0/10 carrier-grade NAT
                    || (b0 == 192 && b1 == 0 && b2 == 0)  // 192.0.0.0/24
                    || (b0 == 198 && (b1 & 0xfe) == 18)   // 198.18.0.0/15
                    || b0 >= 240) {                       // reserved + broadcast
                return true;
            }
            return isInternalIp(address.getHostAddress()); // configured block subnets
        }
        if (address instanceof Inet6Address) {
            return (b[0] & 0xfe) == 0xfc;                 // fc00::/7 unique local
        }
        return true;
    }

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
                // 判断当前请求的URL是否是内网ip；只请求校验后重新构造的URL
                String safeUrl = canonicalOutboundUrl(finalUrl);
                if (safeUrl == null || isInternalIpByUrl(safeUrl)) {
                    logger.error("[-] SSRF check failed. Dangerous url: " + WebUtils.sanitizeLog(finalUrl));
                    return false;  // 内网ip直接return，非内网ip继续判断是否有重定向
                }

                connection = (HttpURLConnection) new URL(safeUrl).openConnection();
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
                    logger.info("redirected url: " + WebUtils.sanitizeLog(finalUrl));
                    if (i == checkTimes) {
                        return false;
                    }
                } else
                    break;
            } while (connection.getResponseCode() != HttpURLConnection.HTTP_OK);
            connection.disconnect();
        } catch (Exception e) {
            logger.error("checkSSRF exception: " + WebUtils.sanitizeLog(e.getMessage()));
            return false;  // fail closed: an url that cannot be verified is not safe
        }
        return true; // 默认返回true
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
            logger.error("[-] SSRF check failed. IP is empty. " + WebUtils.sanitizeLog(strIP));
            return true;
        }

        ArrayList<String> blackSubnets = WebConfig.getSsrfBlockIps();
        for (String subnet : blackSubnets) {
            SubnetUtils utils = new SubnetUtils(subnet);
            if (utils.getInfo().isInRange(strIP)) {
                logger.error("[-] SSRF check failed. Internal IP: " + WebUtils.sanitizeLog(strIP));
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
            logger.error("host2ip exception " + WebUtils.sanitizeLog(e.getMessage()));
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
                    logger.error("Illegal ipv4: " + WebUtils.sanitizeLog(host));
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
                        logger.error("Illegal ipv4: " + WebUtils.sanitizeLog(host));
                        return false;
                    }
                    // start with "0", but not "0"
                    if (ip.startsWith("0") && !ip.equals("0")) {
                        if (Integer.valueOf(ip, 8) >= 256){
                            logger.error("Illegal ipv4: " + WebUtils.sanitizeLog(host));
                            return false;
                        }
                        newDecimalIP.append(Integer.valueOf(ip, 8)).append(".");
                        is_octal = true;
                    }else{
                        if (Integer.valueOf(ip, 10) >= 256) {
                            logger.error("Illegal ipv4: " + WebUtils.sanitizeLog(host));
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
            logger.error("SSRFChecker isOctalIP exception: " + WebUtils.sanitizeLog(e.getMessage()));
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
        String host = SecurityUtil.gethost(url);
        if (host.startsWith("[") && host.endsWith("]")) {
            host = host.substring(1, host.length() - 1);
        }
        return host;
    }

}
