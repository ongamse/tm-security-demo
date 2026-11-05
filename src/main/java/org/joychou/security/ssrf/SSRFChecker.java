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
            logger.error("[-] SSRF safe domain check failed. {}", e.getClass().getSimpleName());
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
                    logger.error("[-] SSRF check failed. Dangerous url.");
                    return false;  // 内网ip直接return，非内网ip继续判断是否有重定向
                }

                URL checked = checkAndGetUrl(finalUrl);
                connection = (HttpURLConnection) checked.openConnection();
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
                    // resolve relative Location headers against the current url
                    finalUrl = resolveRedirect(checked, redirectedUrl);
                    i += 1;  // 重定向次数加1
                    if (i == checkTimes) {
                        return false;
                    }
                } else
                    break;
            } while (connection.getResponseCode() != HttpURLConnection.HTTP_OK);
            connection.disconnect();
        } catch (Exception e) {
            logger.error("[-] SSRF check failed. {}", e.getClass().getSimpleName());
            return false;  // fail closed: a url that cannot be verified is not safe.
        }
        return true; // 默认返回true
    }


    /**
     * Validate an untrusted url and return a {@link URL} that is safe to connect to: the scheme must be
     * http/https, the host must be present and every address it resolves to must not be internal,
     * loopback, link-local, site-local, multicast or the wildcard address. The returned URL is built
     * from the same parsed URI that was validated.
     *
     * @param url untrusted url
     * @return validated URL
     * @throws SSRFException if the url is not allowed
     */
    public static URL checkAndGetUrl(String url) {
        // The only place where the untrusted string is parsed: strict pattern first, then a rebuilt URI.
        URI uri = SecurityUtil.parseHttpUri(url);
        if (null == uri) {
            throw new SSRFException("[-] SSRF check failed. Only well-formed http and https urls are allowed.");
        }
        String host = uri.getHost();
        checkHost(host);
        try {
            // Rebuild the URL from validated components only: fixed scheme literal, checked host, port, path, query.
            String protocol = "https".equals(uri.getScheme()) ? "https" : "http";
            String path = uri.getRawPath();
            StringBuilder file = new StringBuilder(null == path || path.isEmpty() ? "/" : path);
            if (null != uri.getRawQuery()) {
                file.append('?').append(uri.getRawQuery());
            }
            return new URL(protocol, host, uri.getPort(), file.toString());
        } catch (Exception e) {
            throw new SSRFException("[-] SSRF check failed. Illegal url.");
        }
    }


    /**
     * Resolve the Location header of a redirect against the already validated url it came from. Only an absolute
     * http(s) url or an absolute path are accepted; both go through the strict pattern in {@link SecurityUtil}.
     * The result must still be passed to {@link #checkAndGetUrl(String)} before it is requested.
     *
     * @param base     validated url of the response that carried the Location header
     * @param location untrusted Location header value
     * @return absolute url string
     * @throws SSRFException if the Location value is not acceptable
     */
    public static String resolveRedirect(URL base, String location) {
        if (null == location) {
            throw new SSRFException("[-] SSRF check failed. Illegal redirect.");
        }
        int fragment = location.indexOf('#');
        String loc = fragment == -1 ? location : location.substring(0, fragment);
        if (loc.startsWith("/")) {
            String relative = SecurityUtil.parseRelativeUrl(loc, false);
            if (null == relative) {
                throw new SSRFException("[-] SSRF check failed. Illegal redirect.");
            }
            String protocol = "https".equals(base.getProtocol()) ? "https" : "http";
            return protocol + "://" + base.getAuthority() + relative;
        }
        URI absolute = SecurityUtil.parseHttpUri(loc);
        if (null == absolute) {
            throw new SSRFException("[-] SSRF check failed. Illegal redirect.");
        }
        return absolute.toString();
    }


    /**
     * Validate that a host does not point to an internal address. Fails closed.
     *
     * @param host host name or ip
     * @throws SSRFException if the host is empty, cannot be resolved or is internal
     */
    public static void checkHost(String host) {
        if (null == host || host.isEmpty()) {
            throw new SSRFException("[-] SSRF check failed. Empty host.");
        }
        try {
            String ip = host2ip(host);
            if (ip.isEmpty() || isInternalIp(ip)) {
                throw new SSRFException("[-] SSRF check failed. Internal host.");
            }
            String resolveHost = isOctalIP(host) ? decimalIp : host;
            for (InetAddress address : InetAddress.getAllByName(resolveHost)) {
                if (address.isAnyLocalAddress() || address.isLoopbackAddress() || address.isLinkLocalAddress()
                        || address.isSiteLocalAddress() || address.isMulticastAddress()
                        || isInternalIp(address.getHostAddress())) {
                    throw new SSRFException("[-] SSRF check failed. Internal host.");
                }
            }
        } catch (SSRFException e) {
            throw e;
        } catch (Exception e) {
            throw new SSRFException("[-] SSRF check failed. Host cannot be verified.");
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
            logger.error("[-] SSRF check failed. IP is empty.");
            return true;
        }

        ArrayList<String> blackSubnets = WebConfig.getSsrfBlockIps();
        for (String subnet : blackSubnets) {
            SubnetUtils utils = new SubnetUtils(subnet);
            if (utils.getInfo().isInRange(strIP)) {
                logger.error("[-] SSRF check failed. Internal IP.");
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
            logger.error("host2ip exception {}", e.getClass().getSimpleName());
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
                    logger.error("Illegal ipv4.");
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
                        logger.error("Illegal ipv4.");
                        return false;
                    }
                    // start with "0", but not "0"
                    if (ip.startsWith("0") && !ip.equals("0")) {
                        if (Integer.valueOf(ip, 8) >= 256){
                            logger.error("Illegal ipv4.");
                            return false;
                        }
                        newDecimalIP.append(Integer.valueOf(ip, 8)).append(".");
                        is_octal = true;
                    }else{
                        if (Integer.valueOf(ip, 10) >= 256) {
                            logger.error("Illegal ipv4.");
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
            logger.error("SSRFChecker isOctalIP exception: {}", e.getClass().getSimpleName());
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
        // strict pattern + rebuilt URI instead of URL; empty when the url is not a well-formed http(s) url
        return SecurityUtil.gethost(url);
    }

}
