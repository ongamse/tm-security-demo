package org.joychou.security.ssrf;

import java.net.InetAddress;
import java.net.URI;
import java.util.ArrayList;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.net.util.SubnetUtils;
import org.joychou.config.WebConfig;
import org.joychou.security.SecurityUtil;
import org.joychou.util.HttpUtils;
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
            logger.error("SSRFChecker checkURLFckSSRF exception: {}", e.getClass().getName());
            return false;
        }
        return false;
    }

    /**
     * 解析url的ip，判断ip是否是内网ip，所以TTL设置为0的情况不适用。
     * url只允许https或者http，并且设置默认连接超时时间。
     * 该修复方案会主动请求重定向后的链接（只连接已校验过的IP，逐跳校验重定向，校验失败按不安全处理）。
     *
     * @param url        check的url
     * @param checkTimes 设置重定向检测的最大次数，建议设置为10次
     * @return 安全返回true，危险返回false
     */
    public static boolean checkSSRF(String url, int checkTimes) {

        int i = 1;
        String finalUrl = url;
        try {
            while (true) {
                // 判断当前请求的URL是否是内网ip（含八进制等写法）
                if (isInternalIpByUrl(finalUrl)) {
                    logger.error("[-] SSRF check failed. Dangerous url");
                    return false;  // 内网ip直接return，非内网ip继续判断是否有重定向
                }

                // Resolve the host once, validate every address and connect to exactly those
                // addresses (no second DNS lookup, so DNS rebinding cannot swap the address).
                // The request URI is rebuilt from the validated components (see SecurityUtil.OutboundTarget).
                SecurityUtil.OutboundTarget target = SecurityUtil.resolveOutboundTarget(finalUrl);
                if (target == null) {
                    logger.error("[-] SSRF check failed. Illegal or internal url");
                    return false;
                }

                // redirects are not followed automatically, each hop is validated by this loop
                String location = HttpUtils.pinnedRedirectLocation(target);
                if (null == location) {
                    return true;  // no redirect, the url chain is safe
                }
                // Location may be relative; make it absolute against the validated current target,
                // the next loop iteration validates the new hop from scratch.
                finalUrl = nextHop(target.getUri(), location);
                if (finalUrl == null) {
                    logger.error("[-] SSRF check failed. Unsupported redirect location");
                    return false;
                }
                i += 1;  // 重定向次数加1
                logger.info("redirected to the next hop");
                if (i >= checkTimes) {
                    return false;
                }
            }
        } catch (Exception e) {
            logger.error("SSRFChecker checkSSRF exception: {}", e.getClass().getName());
            return false;  // fail closed: a url that cannot be verified is not considered safe
        }
    }


    /**
     * Turn a redirect Location into an absolute url text: absolute http(s) urls are passed on as they are
     * (and validated by the caller's next iteration), absolute-path and relative-path references are
     * attached to the scheme/authority of the already validated current URI. Anything else (other
     * schemes, scheme-relative "//host", whitespace or backslashes) is rejected.
     *
     * @return the next hop url text, or null when the location is not supported (fail closed)
     */
    private static String nextHop(URI current, String location) {
        if (location == null || location.isEmpty()) {
            return null;
        }
        if (SecurityUtil.isHttp(location)) {
            return location;
        }
        if (location.startsWith("//") || location.indexOf(':') >= 0 || location.indexOf('\\') >= 0) {
            return null;
        }
        String base = current.getScheme() + "://" + current.getRawAuthority();
        if (location.startsWith("/")) {
            return base + location;
        }
        String dir = current.getRawPath() == null ? "/" : current.getRawPath();
        dir = dir.substring(0, dir.lastIndexOf('/') + 1);
        if (dir.isEmpty()) {
            dir = "/";
        }
        return base + dir + location;
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
                logger.error("[-] SSRF check failed. IP is in a blocked subnet.");
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
            logger.error("host2ip exception {}", e.getClass().getName());
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
                    logger.error("Illegal ipv4: too many parts");
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
                        logger.error("Illegal ipv4: part is not a number");
                        return false;
                    }
                    // start with "0", but not "0"
                    if (ip.startsWith("0") && !ip.equals("0")) {
                        if (Integer.valueOf(ip, 8) >= 256){
                            logger.error("Illegal ipv4: octal part out of range");
                            return false;
                        }
                        newDecimalIP.append(Integer.valueOf(ip, 8)).append(".");
                        is_octal = true;
                    }else{
                        if (Integer.valueOf(ip, 10) >= 256) {
                            logger.error("Illegal ipv4: decimal part out of range");
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
            logger.error("SSRFChecker isOctalIP exception: {}", e.getClass().getName());
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
        if (!SecurityUtil.isHttp(url)) {
            return "";
        }
        // strict RFC 3986 parser (rejects backslash / userinfo confusion); empty host when malformed
        return SecurityUtil.gethost(url);
    }

}
