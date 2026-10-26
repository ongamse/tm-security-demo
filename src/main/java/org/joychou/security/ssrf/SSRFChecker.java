package org.joychou.security.ssrf;

import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.URI;
import java.net.URL;
import java.util.ArrayList;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.net.util.SubnetUtils;
import org.joychou.config.WebConfig;
import org.joychou.security.SecurityUtil;
import static org.joychou.security.SecurityUtil.sanitizeLogOutput;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public class SSRFChecker {

    private static final Logger logger = LoggerFactory.getLogger(SSRFChecker.class);
    private static String decimalIp;

    public static boolean checkURLFckSSRF(String url) {
        if (null == url) {
            return false;
        }

        ArrayList<String> ssrfSafeDomains = WebConfig.getSsrfSafeDomains();
        try {
            String host = SecurityUtil.gethost(url);

            // Must be http or https
            if (!SecurityUtil.isHttp(url)) {
                return false;
            }

            boolean domainAllowed = false;
            if (ssrfSafeDomains.contains(host)) {
                domainAllowed = true;
            } else {
                for (String ssrfSafeDomain : ssrfSafeDomains) {
                    if (host.endsWith("." + ssrfSafeDomain)) {
                        domainAllowed = true;
                        break;
                    }
                }
            }

            if (!domainAllowed) {
                return false;
            }

            // Even for whitelisted domains, resolve DNS and reject internal IPs
            // to prevent DNS rebinding and spoofed DNS records
            if (isInternalIpByUrl(url)) {
                logger.error("[-] SSRF check failed. Whitelisted domain resolves to internal IP: " + sanitizeLogOutput(host));
                return false;
            }

            return true;
        } catch (Exception e) {
            logger.error(e.toString());
            return false;
        }
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

        if (url == null || !SecurityUtil.isHttp(url)) {
            return false;
        }

        HttpURLConnection connection;
        int connectTime = 5 * 1000;
        int i = 1;
        String finalUrl = url;
        try {
            do {
                // Check the URL is HTTP(S) and its resolved IP is not internal
                if (!SecurityUtil.isHttp(finalUrl)) {
                    logger.error("[-] SSRF check failed. Non-HTTP redirect: " + sanitizeLogOutput(finalUrl));
                    return false;
                }

                if (isInternalIpByUrl(finalUrl)) {
                    logger.error("[-] SSRF check failed. Dangerous url: " + sanitizeLogOutput(finalUrl));
                    return false;
                }

                connection = (HttpURLConnection) new URL(finalUrl).openConnection();
                connection.setInstanceFollowRedirects(false);
                connection.setUseCaches(false);
                connection.setConnectTimeout(connectTime);
                connection.connect();
                int responseCode = connection.getResponseCode();
                if (responseCode >= 300 && responseCode <= 307 && responseCode != 304 && responseCode != 306) {
                    String redirectedUrl = connection.getHeaderField("Location");
                    if (null == redirectedUrl)
                        break;
                    finalUrl = redirectedUrl;
                    i += 1;
                    logger.info("redirected url: " + sanitizeLogOutput(finalUrl));
                    if (i == checkTimes) {
                        return false;
                    }
                } else
                    break;
            } while (connection.getResponseCode() != HttpURLConnection.HTTP_OK);
            connection.disconnect();
        } catch (Exception e) {
            // Fail closed: if validation itself errors out, treat as unsafe
            logger.error("[-] SSRF check exception: " + sanitizeLogOutput(e.getMessage()));
            return false;
        }
        return true;
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
     * Check whether an IP is an internal/private/reserved address.
     * Covers loopback (127.0.0.0/8, ::1), link-local (169.254.0.0/16, fe80::/10),
     * site-local / RFC1918 (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16),
     * IPv6 ULA (fd00::/8), and any-local (0.0.0.0, ::).
     *
     * @param strIP ip string (IPv4 or IPv6)
     * @return true if internal/private, false otherwise
     */
    public static boolean isInternalIp(String strIP) {
        if (StringUtils.isEmpty(strIP)) {
            logger.error("[-] SSRF check failed. IP is empty. " + sanitizeLogOutput(strIP));
            return true;
        }

        try {
            InetAddress addr = InetAddress.getByName(strIP);
            // Reject loopback (127/8, ::1), link-local (169.254/16, fe80::/10),
            // site-local (10/8, 172.16/12, 192.168/16), any-local (0.0.0.0, ::)
            if (addr.isLoopbackAddress() || addr.isLinkLocalAddress()
                    || addr.isSiteLocalAddress() || addr.isAnyLocalAddress()) {
                logger.error("[-] SSRF check failed. Internal IP: " + sanitizeLogOutput(strIP));
                return true;
            }
            // IPv6 Unique Local Addresses (fd00::/8) — not covered by isSiteLocalAddress in Java 8
            byte[] addrBytes = addr.getAddress();
            if (addrBytes.length == 16 && (addrBytes[0] & 0xFF) == 0xFD) {
                logger.error("[-] SSRF check failed. Internal IP (IPv6 ULA): " + sanitizeLogOutput(strIP));
                return true;
            }
        } catch (Exception e) {
            logger.error("[-] SSRF check failed. Cannot parse IP: " + sanitizeLogOutput(strIP));
            return true;
        }

        // Additionally check against configured block IP subnets (IPv4 CIDR)
        ArrayList<String> blackSubnets = WebConfig.getSsrfBlockIps();
        for (String subnet : blackSubnets) {
            try {
                SubnetUtils utils = new SubnetUtils(subnet);
                utils.setInclusiveHostCount(true);
                if (utils.getInfo().isInRange(strIP)) {
                    logger.error("[-] SSRF check failed. Internal IP: " + sanitizeLogOutput(strIP));
                    return true;
                }
            } catch (IllegalArgumentException e) {
                // Skip entries that SubnetUtils cannot parse (e.g. IPv6 subnets)
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
            logger.error("host2ip exception " + sanitizeLogOutput(e.getMessage()));
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
                    logger.error("Illegal ipv4: " + sanitizeLogOutput(host));
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
                        logger.error("Illegal ipv4: " + sanitizeLogOutput(host));
                        return false;
                    }
                    // start with "0", but not "0"
                    if (ip.startsWith("0") && !ip.equals("0")) {
                        if (Integer.valueOf(ip, 8) >= 256){
                            logger.error("Illegal ipv4: " + sanitizeLogOutput(host));
                            return false;
                        }
                        newDecimalIP.append(Integer.valueOf(ip, 8)).append(".");
                        is_octal = true;
                    }else{
                        if (Integer.valueOf(ip, 10) >= 256) {
                            logger.error("Illegal ipv4: " + sanitizeLogOutput(host));
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
            logger.error("SSRFChecker isOctalIP exception: " + sanitizeLogOutput(e.getMessage()));
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
            // use URI instead of URL
            URI u = new URI(url);
            if (SecurityUtil.isHttp(url)) {
                return u.getHost();
            }
            return "";
        } catch (Exception e) {
            return "";
        }
    }

}
