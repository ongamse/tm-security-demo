package org.joychou.security.ssrf;

import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLConnection;
import java.util.ArrayList;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.net.util.SubnetUtils;
import org.joychou.config.WebConfig;
import org.joychou.security.SecurityUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public class SSRFChecker {

    private static final Logger logger = LoggerFactory.getLogger(SSRFChecker.class);
    private static String decimalIp;

    private static final String URL_HOST_CHARS = "abcdefghijklmnopqrstuvwxyz0123456789.-";
    private static final String URL_PATH_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
            + "-._~!$&'()*+,;=:@/%";
    private static final String URL_QUERY_CHARS = URL_PATH_CHARS + "?";

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
                    logger.error("[-] SSRF check failed. Dangerous url: " + finalUrl);
                    return false;  // 内网ip直接return，非内网ip继续判断是否有重定向
                }

                connection = (HttpURLConnection) validateUrl(finalUrl).openConnection();
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
                    logger.info("redirected url: " + finalUrl);
                    if (i == checkTimes) {
                        return false;
                    }
                } else
                    break;
            } while (connection.getResponseCode() != HttpURLConnection.HTTP_OK);
            connection.disconnect();
        } catch (SSRFException e) {
            logger.error("[-] SSRF check failed. Dangerous url: " + finalUrl);
            return false;  // not http/https or internal ip (e.g. a redirect target) is never safe
        } catch (Exception e) {
            return true;  // 如果异常了，认为是安全的，防止是超时导致的异常而验证不成功。
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
        if (host == null || host.equals("")) {
            return true; // 异常URL当成内网IP等非法URL处理
        }

        // Convert octal ip to decimal ip first, then resolve every address of the host.
        String target = host;
        if (isOctalIP(host)) {
            target = decimalIp;
        }

        InetAddress[] addresses;
        try {
            addresses = InetAddress.getAllByName(target); // send dns request
        } catch (Exception e) {
            logger.error("isInternalIpByUrl exception " + e.getMessage());
            return true; // 如果域名转换为IP异常，则认为是非法URL
        }

        for (InetAddress address : addresses) {
            if (isInternalAddress(address)) {
                return true;
            }
        }
        return false;
    }


    /**
     * Check a resolved address: loopback, any-local, link-local (including the 169.254.169.254
     * metadata address), site-local, multicast, IPv6 unique-local, carrier-grade NAT, and the
     * configured blocked subnets.
     *
     * @return true if the address is internal or otherwise not allowed
     */
    public static boolean isInternalAddress(InetAddress address) {
        if (address == null) {
            return true;
        }
        if (address.isAnyLocalAddress() || address.isLoopbackAddress() || address.isLinkLocalAddress()
                || address.isSiteLocalAddress() || address.isMulticastAddress()) {
            logger.error("[-] SSRF check failed. Internal IP: " + address.getHostAddress());
            return true;
        }
        byte[] raw = address.getAddress();
        if (raw.length == 16 && (raw[0] & 0xFE) == 0xFC) {
            return true; // IPv6 unique local fc00::/7
        }
        if (raw.length == 4 && (raw[0] & 0xFF) == 100 && (raw[1] & 0xC0) == 64) {
            return true; // 100.64.0.0/10 carrier-grade NAT
        }
        if (raw.length == 4) {
            return isInternalIp(address.getHostAddress());
        }
        return false;
    }


    /**
     * Validate an untrusted URL before any outbound request: only http/https with a well-formed
     * host that resolves exclusively to non-internal addresses.
     *
     * @param url untrusted url
     * @return the validated URL
     * @throws SSRFException if the url is not allowed
     */
    public static URL validateUrl(String url) {
        try {
            return new URL(safeUrl(url));
        } catch (java.net.MalformedURLException e) {
            throw new SSRFException("[-] SSRF check failed. Malformed url.");
        }
    }


    /**
     * Central SSRF control. Validates an untrusted URL and returns a NEW url string that is safe to
     * hand to an HTTP client; callers must request the returned value, never the raw request string.
     * <ul>
     *   <li>only http/https, no userinfo, host parsed identically by java.net.URI and the raw authority</li>
     *   <li>host must match an entry of the configured SSRF safe-domain list and must not resolve to an
     *       internal / loopback / link-local address (see {@link #safeHost(String)})</li>
     *   <li>the result is rebuilt: constant scheme, host copied from the configured allowlist entry, parsed
     *       integer port, path and query copied one character at a time from fixed allowlists of url
     *       characters (any other character rejects the url)</li>
     * </ul>
     *
     * @param url untrusted url
     * @return the rebuilt, validated url
     * @throws SSRFException if the url is not allowed
     */
    public static String safeUrl(String url) {
        if (url == null || !SecurityUtil.isHttp(url)) {
            throw new SSRFException("[-] SSRF check failed. Only http and https are allowed.");
        }
        String host = SecurityUtil.gethost(url);
        if (host.isEmpty()) {
            throw new SSRFException("[-] SSRF check failed. Illegal host.");
        }
        URI uri;
        try {
            uri = new URI(url);
        } catch (URISyntaxException e) {
            throw new SSRFException("[-] SSRF check failed. Malformed url.");
        }
        if (uri.getRawUserInfo() != null) {
            throw new SSRFException("[-] SSRF check failed. Userinfo is not allowed.");
        }
        int port = uri.getPort();
        if (port != -1 && (port < 1 || port > 65535)) {
            throw new SSRFException("[-] SSRF check failed. Illegal port.");
        }
        String path = uri.getRawPath() == null ? "" : uri.getRawPath();
        String safePath = copyAllowed(path, URL_PATH_CHARS);
        if (safePath == null || (!safePath.isEmpty() && !safePath.startsWith("/"))) {
            throw new SSRFException("[-] SSRF check failed. Illegal path.");
        }
        String safeQuery = null;
        if (uri.getRawQuery() != null) {
            safeQuery = copyAllowed(uri.getRawQuery(), URL_QUERY_CHARS);
            if (safeQuery == null) {
                throw new SSRFException("[-] SSRF check failed. Illegal query.");
            }
        }

        StringBuilder rebuilt = new StringBuilder("https".equalsIgnoreCase(uri.getScheme()) ? "https" : "http");
        rebuilt.append("://").append(safeHost(host));
        if (port != -1) {
            rebuilt.append(':').append(port);
        }
        rebuilt.append(safePath.isEmpty() ? "/" : safePath);
        if (safeQuery != null) {
            rebuilt.append('?').append(safeQuery);
        }
        return rebuilt.toString();
    }


    /**
     * Same as {@link #safeUrl(String)} but returns null instead of throwing when the url is not allowed.
     */
    public static String safeUrlOrNull(String url) {
        try {
            return safeUrl(url);
        } catch (SSRFException e) {
            logger.error(e.getMessage());
            return null;
        }
    }


    /**
     * Validate a host name against the configured SSRF safe-domain list and the internal-address block
     * and return the host rebuilt from the configured allowlist entry (an exact entry, or a sub-domain
     * label prefix made of host characters followed by the entry).
     *
     * @param host untrusted host name
     * @return the validated host
     * @throws SSRFException if the host is not allowed
     */
    public static String safeHost(String host) {
        String labels = host == null ? null : copyAllowed(host.toLowerCase(), URL_HOST_CHARS);
        if (labels == null || labels.isEmpty() || labels.startsWith(".") || labels.contains("..")) {
            throw new SSRFException("[-] SSRF check failed. Illegal host.");
        }
        String safe = null;
        for (String entry : WebConfig.getSsrfSafeDomains()) {
            String domain = entry.trim();
            String lowerDomain = domain.toLowerCase();
            if (domain.isEmpty()) {
                continue;
            }
            if (labels.equals(lowerDomain)) {
                safe = domain;
                break;
            }
            if (labels.endsWith("." + lowerDomain)) {
                String prefix = labels.substring(0, labels.length() - lowerDomain.length() - 1);
                if (!prefix.isEmpty()) {
                    safe = prefix + "." + domain;
                    break;
                }
            }
        }
        if (safe == null) {
            throw new SSRFException("[-] SSRF check failed. Host is not in the safe-domain list.");
        }
        if (isInternalIpByUrl("http://" + safe + "/")) {
            throw new SSRFException("[-] SSRF check failed. Dangerous host.");
        }
        return safe;
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
     * Validate the url and open a connection that does not follow redirects, so a validated
     * public host cannot bounce the request to an internal address.
     *
     * @throws SSRFException if the url is not allowed
     * @throws java.io.IOException if the connection cannot be opened
     */
    public static URLConnection openNoRedirect(String url) throws java.io.IOException {
        URLConnection connection = validateUrl(url).openConnection();
        if (connection instanceof HttpURLConnection) {
            ((HttpURLConnection) connection).setInstanceFollowRedirects(false);
        }
        return connection;
    }


    /**
     * 使用SubnetUtils库判断ip是否在内网网段
     *
     * @param strIP ip字符串
     * @return 如果是内网ip，返回true，否则返回false。
     */
    public static boolean isInternalIp(String strIP) {
        if (StringUtils.isEmpty(strIP)) {
            logger.error("[-] SSRF check failed. IP is empty. " + strIP);
            return true;
        }

        ArrayList<String> blackSubnets = WebConfig.getSsrfBlockIps();
        for (String subnet : blackSubnets) {
            SubnetUtils utils = new SubnetUtils(subnet);
            if (utils.getInfo().isInRange(strIP)) {
                logger.error("[-] SSRF check failed. Internal IP: " + strIP);
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
            logger.error("host2ip exception " + e.getMessage());
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
                    logger.error("Illegal ipv4: " + host);
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
                        logger.error("Illegal ipv4: " + host);
                        return false;
                    }
                    // start with "0", but not "0"
                    if (ip.startsWith("0") && !ip.equals("0")) {
                        if (Integer.valueOf(ip, 8) >= 256){
                            logger.error("Illegal ipv4: " + host);
                            return false;
                        }
                        newDecimalIP.append(Integer.valueOf(ip, 8)).append(".");
                        is_octal = true;
                    }else{
                        if (Integer.valueOf(ip, 10) >= 256) {
                            logger.error("Illegal ipv4: " + host);
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
            logger.error("SSRFChecker isOctalIP exception: " + e.getMessage());
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
        try {
            // gethost parses with URI and rejects URLs that java.net.URL would parse differently
            if (SecurityUtil.isHttp(url)) {
                return SecurityUtil.gethost(url);
            }
            return "";
        } catch (Exception e) {
            return "";
        }
    }

}
