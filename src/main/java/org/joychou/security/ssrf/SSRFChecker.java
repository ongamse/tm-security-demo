package org.joychou.security.ssrf;

import java.net.HttpURLConnection;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.net.util.SubnetUtils;
import org.joychou.config.WebConfig;
import org.joychou.security.SecurityUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public class SSRFChecker {

    private static final Logger logger = LoggerFactory.getLogger(SSRFChecker.class);

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
                // 判断当前请求的URL是否是内网ip；连接使用校验后重新组装的URL
                URL checkedUrl = safeUrl(finalUrl);
                if (checkedUrl == null) {
                    logger.error("[-] SSRF check failed. Dangerous url.");
                    return false;  // 内网ip直接return，非内网ip继续判断是否有重定向
                }

                connection = (HttpURLConnection) checkedUrl.openConnection();
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
                    logger.info("redirected");
                    if (i == checkTimes) {
                        return false;
                    }
                } else
                    break;
            } while (connection.getResponseCode() != HttpURLConnection.HTTP_OK);
            connection.disconnect();
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
        // Malformed urls and hosts that cannot be resolved are treated as illegal (internal).
        return safeUrl(url) == null;
    }


    /**
     * Validate an untrusted http(s) url and rebuild it from the validated components.
     * The url is parsed once by {@link SecurityUtil#parseHttpUrl(String)}, the host is resolved
     * and every resolved address must be public. IP literals (including octal / short forms)
     * are replaced by the address that was actually checked.
     *
     * @return the rebuilt url, or null if the url is malformed or points to an internal address
     */
    public static URL safeUrl(String url) {
        SecurityUtil.ParsedUrl parsed = SecurityUtil.parseHttpUrl(url);
        if (parsed == null) {
            return null;
        }
        InetAddress addr = resolvePublic(parsed.getHost());
        if (addr == null) {
            return null;
        }
        String host = isNumberOrDot(parsed.getHost()) ? addr.getHostAddress() : parsed.getHost();
        try {
            return new URL(parsed.getScheme(), host, parsed.getPort(), parsed.getFile());
        } catch (MalformedURLException e) {
            return null;
        }
    }


    /**
     * Validate a bare host name or IP literal.
     *
     * @return the checked IP address of the host, or null if it cannot be resolved or is internal
     */
    public static String safeHost(String host) {
        InetAddress addr = resolvePublic(host);
        return addr == null ? null : addr.getHostAddress();
    }


    /**
     * Resolve a host and make sure that none of its addresses is internal.
     *
     * @return a public address of the host, or null
     */
    private static InetAddress resolvePublic(String host) {
        if (StringUtils.isEmpty(host)) {
            return null;
        }
        String decimal = octalToDecimal(host);
        String lookup = decimal != null ? decimal : host;
        try {
            // send dns request
            InetAddress[] addrs = InetAddress.getAllByName(lookup);
            InetAddress result = null;
            for (InetAddress a : addrs) {
                if (a instanceof Inet6Address) {
                    if (isInternalIp6((Inet6Address) a)) {
                        logger.error("[-] SSRF check failed. Internal IPv6: " + a.getHostAddress());
                        return null;
                    }
                } else if (a.isAnyLocalAddress() || a.isLoopbackAddress() || a.isLinkLocalAddress()
                        || a.isSiteLocalAddress() || a.isMulticastAddress()
                        || isInternalIp(a.getHostAddress())) {
                    return null;
                }
                if (result == null) {
                    result = a;
                }
            }
            return result;
        } catch (Exception e) {
            logger.error("resolvePublic exception " + e.getMessage());
            return null;
        }
    }


    private static boolean isInternalIp6(Inet6Address a) {
        byte[] b = a.getAddress();
        return a.isAnyLocalAddress() || a.isLoopbackAddress() || a.isLinkLocalAddress()
                || a.isSiteLocalAddress() || a.isMulticastAddress()
                || (b[0] & 0xfe) == 0xfc;  // fc00::/7 unique local
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
         String decimal = octalToDecimal(host);
         if (decimal != null) {
             host = decimal;
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
     * Check whether the host is an octal IP.
     * @return Octal ip returns true, others return false. 012.23.78.233 return true. 012.0x17.78.233 return false.
     */
    public static boolean isOctalIP(String host) {
        return octalToDecimal(host) != null;
    }


    /**
     * Convert an octal ipv4 host to decimal. Stateless, so it is safe to call concurrently.
     *
     * @return the decimal ip when the host is an octal ip, otherwise null
     */
    private static String octalToDecimal(String host) {
        try {
            String[] ipParts = host.split("\\.");
            StringBuilder newDecimalIP = new StringBuilder();
            boolean is_octal = false;

            // Octal ip only has number and dot character.
            if (isNumberOrDot(host)) {

                // not support ipv6
                if (ipParts.length > 4) {
                    logger.error("Illegal ipv4: " + host);
                    return null;
                }

                // 01205647351
                if( ipParts.length == 1 && host.startsWith("0") ) {
                    return Integer.valueOf(host, 8).toString();
                }

                // 012.23.78.233
                for(String ip : ipParts) {
                    if (!isNumber(ip)){
                        logger.error("Illegal ipv4: " + host);
                        return null;
                    }
                    // start with "0", but not "0"
                    if (ip.startsWith("0") && !ip.equals("0")) {
                        if (Integer.valueOf(ip, 8) >= 256){
                            logger.error("Illegal ipv4: " + host);
                            return null;
                        }
                        newDecimalIP.append(Integer.valueOf(ip, 8)).append(".");
                        is_octal = true;
                    }else{
                        if (Integer.valueOf(ip, 10) >= 256) {
                            logger.error("Illegal ipv4: " + host);
                            return null;
                        }
                        newDecimalIP.append(ip).append(".");
                    }
                }
                // delete last char .
                if (is_octal) {
                    return newDecimalIP.substring(0, newDecimalIP.lastIndexOf("."));
                }
            }
            return null;
        } catch (Exception e){
            logger.error("SSRFChecker isOctalIP exception: " + e.getMessage());
            return null;
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

}
