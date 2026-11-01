package org.joychou.security.ssrf;

import java.io.ByteArrayOutputStream;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.net.util.SubnetUtils;
import org.joychou.config.WebConfig;
import org.joychou.security.LogSafe;
import org.joychou.security.SecurityUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public class SSRFChecker {

    private static final Logger logger = LoggerFactory.getLogger(SSRFChecker.class);
    private static String decimalIp;

    /** scheme://authority path ?query #fragment (fragment is dropped when the url is rebuilt). */
    private static final Pattern HTTP_URL_PATTERN =
            Pattern.compile("^([a-zA-Z][a-zA-Z0-9+.-]*)://([^/?#]*)([^?#]*)(?:\\?([^#]*))?(?:#.*)?$");

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
            logger.error("checkURLFckSSRF failed: {}", LogSafe.errorName(e));
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
                    logger.error("[-] SSRF check failed. Dangerous url: {}", LogSafe.fingerprint(finalUrl));
                    return false;  // 内网ip直接return，非内网ip继续判断是否有重定向
                }

                // Only http/https, no user info, and every resolved address must be public
                // before this checker itself opens a connection to the url.
                URI validated;
                try {
                    validated = validateHttpUrl(finalUrl);
                } catch (SSRFException e) {
                    logger.error("[-] SSRF check failed. Dangerous url: {}", LogSafe.fingerprint(finalUrl));
                    return false;
                }

                connection = (HttpURLConnection) validated.toURL().openConnection();
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
                    try {
                        finalUrl = validated.resolve(redirectedUrl).toString();
                    } catch (IllegalArgumentException e) {
                        return false;
                    }
                    i += 1;  // 重定向次数加1
                    logger.info("redirected url: {}", LogSafe.fingerprint(finalUrl));
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

        String host = url2host(url);
        if (host == null || host.equals("")) {
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

        // Only numeric IP literals are accepted here (never trigger a DNS lookup); fail closed otherwise.
        boolean isLiteral = strIP.indexOf(':') >= 0 || strIP.matches("^[0-9.]+$");
        if (!isLiteral) {
            logger.error("[-] SSRF check failed. Not an IP literal.");
            return true;
        }

        InetAddress addr;
        try {
            addr = InetAddress.getByName(strIP);
        } catch (Exception e) {
            logger.error("[-] SSRF check failed. Illegal IP: {}", LogSafe.fingerprint(strIP));
            return true;
        }

        if (isInternalAddress(addr)) {
            logger.error("[-] SSRF check failed. Internal IP: {}", LogSafe.fingerprint(strIP));
            return true;
        }

        return false;

    }


    /**
     * Check whether an address is loopback, link-local (including cloud metadata 169.254.169.254),
     * private, carrier-grade NAT, multicast, reserved, or inside the configured blocked subnets.
     *
     * @param addr resolved address
     * @return true if the address must not be requested
     */
    public static boolean isInternalAddress(InetAddress addr) {
        if (addr.isAnyLocalAddress() || addr.isLoopbackAddress() || addr.isLinkLocalAddress()
                || addr.isSiteLocalAddress() || addr.isMulticastAddress()) {
            return true;
        }

        byte[] raw = addr.getAddress();
        if (raw.length == 4) {
            int b0 = raw[0] & 0xff;
            int b1 = raw[1] & 0xff;
            if (b0 == 0 || b0 >= 240 || (b0 == 100 && b1 >= 64 && b1 <= 127)) {
                return true;
            }
            ArrayList<String> blackSubnets = WebConfig.getSsrfBlockIps();
            for (String subnet : blackSubnets) {
                SubnetUtils utils = new SubnetUtils(subnet);
                if (utils.getInfo().isInRange(addr.getHostAddress())) {
                    return true;
                }
            }
        } else if (raw.length == 16 && (raw[0] & 0xfe) == 0xfc) {
            return true; // IPv6 unique local addresses fc00::/7
        }
        return false;
    }


    /**
     * Resolve a host once and require every resulting address to be public.
     *
     * @param host host name or IP literal
     * @return the validated addresses
     * @throws UnknownHostException if the host cannot be resolved
     * @throws SSRFException        if any resolved address is internal
     */
    public static InetAddress[] resolvePublicAddresses(String host) throws UnknownHostException {
        if (host == null || host.isEmpty()) {
            throw new SSRFException("[-] SSRF check failed. Empty host.");
        }
        InetAddress[] addrs = InetAddress.getAllByName(host);
        for (InetAddress addr : addrs) {
            if (isInternalAddress(addr)) {
                logger.error("[-] SSRF check failed. Resolved address is internal: {}",
                        LogSafe.fingerprint(addr.getHostAddress()));
                throw new SSRFException("[-] SSRF check failed. Internal address.");
            }
        }
        return addrs;
    }


    /**
     * Validate a user supplied URL for an outgoing request: http/https only, no user info,
     * and the host must resolve exclusively to public addresses.
     *
     * @param url user supplied url
     * @return the parsed, validated URI
     * @throws SSRFException if the url is not allowed
     */
    public static URI validateHttpUrl(String url) {
        if (url == null) {
            throw new SSRFException("[-] SSRF check failed. Empty url.");
        }
        // The untrusted string is split with a strict pattern (never parsed by java.net.URI/URL);
        // the returned URI is freshly built from validated components only.
        Matcher m = HTTP_URL_PATTERN.matcher(url.trim());
        if (!m.matches()) {
            throw new SSRFException("[-] SSRF check failed. Illegal url.");
        }

        final String scheme;
        if ("https".equalsIgnoreCase(m.group(1))) {
            scheme = "https";
        } else if ("http".equalsIgnoreCase(m.group(1))) {
            scheme = "http";
        } else {
            throw new SSRFException("[-] SSRF check failed. Only http/https is allowed.");
        }

        String authority = m.group(2);
        if (authority.indexOf('@') >= 0) {
            throw new SSRFException("[-] SSRF check failed. User info is not allowed.");
        }
        String host = SecurityUtil.gethost(scheme + "://" + authority);
        if (host.isEmpty() || !isSafeHostSyntax(host)) {
            throw new SSRFException("[-] SSRF check failed. Illegal host.");
        }

        int port = -1;
        int portSep = authority.lastIndexOf(':');
        if (portSep >= 0 && portSep > authority.lastIndexOf(']') && portSep < authority.length() - 1) {
            port = Integer.parseInt(authority.substring(portSep + 1)); // digits only, max 5 (host pattern)
            if (port < 1 || port > 65535) {
                throw new SSRFException("[-] SSRF check failed. Illegal port.");
            }
        }

        String path = decodeComponent(m.group(3));
        if (path.isEmpty()) {
            path = "/";
        }
        String query = m.group(4) == null ? null : decodeComponent(m.group(4));

        try {
            resolvePublicAddresses(host);
            // The multi-argument constructor quotes every illegal character in path/query.
            return new URI(scheme, null, host, port, path, query, null);
        } catch (UnknownHostException e) {
            throw new SSRFException("[-] SSRF check failed. Unknown host.");
        } catch (URISyntaxException e) {
            throw new SSRFException("[-] SSRF check failed. Illegal url.");
        }
    }


    /**
     * Reject host spellings that a resolver might read as an obfuscated IPv4 address
     * (decimal/octal/hex integers, short or zero-padded dotted forms).
     */
    private static boolean isSafeHostSyntax(String host) {
        if (host.startsWith("[")) {
            return true; // IPv6 literal, syntax already checked
        }
        if (host.matches("^[0-9.]+$")) {
            String[] parts = host.split("\\.", -1);
            if (parts.length != 4) {
                return false;
            }
            for (String part : parts) {
                if (part.isEmpty() || part.length() > 3 || (part.length() > 1 && part.startsWith("0"))
                        || Integer.parseInt(part) > 255) {
                    return false;
                }
            }
            return true;
        }
        String lastLabel = host.substring(host.lastIndexOf('.') + 1);
        return !lastLabel.matches("^0[xX][0-9a-fA-F]*$") && !lastLabel.matches("^[0-9]+$");
    }


    /**
     * Strictly percent-decode a path or query component (UTF-8). Delimiter-changing escapes
     * (such as %2F, %26, %3D, %23, %25) and control characters are rejected so the rebuilt URI keeps
     * the original structure after being re-encoded.
     */
    public static String decodeComponent(String raw) {
        if (raw == null) {
            return "";
        }
        StringBuilder out = new StringBuilder(raw.length());
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        int i = 0;
        while (i < raw.length()) {
            char ch = raw.charAt(i);
            if (ch == '%') {
                if (i + 2 >= raw.length()) {
                    throw new SSRFException("[-] SSRF check failed. Illegal url.");
                }
                int hi = Character.digit(raw.charAt(i + 1), 16);
                int lo = Character.digit(raw.charAt(i + 2), 16);
                if (hi < 0 || lo < 0) {
                    throw new SSRFException("[-] SSRF check failed. Illegal url.");
                }
                bytes.write((hi << 4) | lo);
                i += 3;
                continue;
            }
            flushDecoded(bytes, out);
            if (Character.isISOControl(ch) || Character.isWhitespace(ch) || ch == '\\') {
                throw new SSRFException("[-] SSRF check failed. Illegal url.");
            }
            out.append(ch);
            i++;
        }
        flushDecoded(bytes, out);
        return out.toString();
    }


    private static void flushDecoded(ByteArrayOutputStream bytes, StringBuilder out) {
        if (bytes.size() == 0) {
            return;
        }
        String decoded = new String(bytes.toByteArray(), StandardCharsets.UTF_8);
        bytes.reset();
        for (int k = 0; k < decoded.length(); k++) {
            char c = decoded.charAt(k);
            if (c == '\uFFFD' || Character.isISOControl(c) || Character.isWhitespace(c)
                    || "/?#&=+;%\\@:".indexOf(c) >= 0) {
                throw new SSRFException("[-] SSRF check failed. Illegal url.");
            }
        }
        out.append(decoded);
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
            logger.error("host2ip exception: {}", LogSafe.errorName(e));
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
                    logger.error("Illegal ipv4: {}", LogSafe.fingerprint(host));
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
                        logger.error("Illegal ipv4: {}", LogSafe.fingerprint(host));
                        return false;
                    }
                    // start with "0", but not "0"
                    if (ip.startsWith("0") && !ip.equals("0")) {
                        if (Integer.valueOf(ip, 8) >= 256){
                            logger.error("Illegal ipv4: {}", LogSafe.fingerprint(host));
                            return false;
                        }
                        newDecimalIP.append(Integer.valueOf(ip, 8)).append(".");
                        is_octal = true;
                    }else{
                        if (Integer.valueOf(ip, 10) >= 256) {
                            logger.error("Illegal ipv4: {}", LogSafe.fingerprint(host));
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
            logger.error("SSRFChecker isOctalIP exception: {}", LogSafe.errorName(e));
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
        return SecurityUtil.gethost(url);
    }
}
