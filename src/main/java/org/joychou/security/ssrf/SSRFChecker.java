package org.joychou.security.ssrf;

import java.net.HttpURLConnection;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.ArrayList;
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
    private static final String PCT = "%[0-9A-Fa-f]{2}";
    // Strict RFC 3986 absolute http(s) url: scheme, optional userinfo, host (reg-name or IP literal),
    // optional port, path, optional query, optional fragment. Anything else (whitespace, control
    // characters, backslash, non-ASCII, ...) does not match.
    private static final Pattern HTTP_URL_PATTERN = Pattern.compile(
            "(?i:(https?))://"
                    + "(?:((?:" + PCT + "|[A-Za-z0-9._~!$&'()*+,;=:-])*)@)?"
                    + "([A-Za-z0-9][A-Za-z0-9.-]*|\\[[0-9A-Fa-f:.]+\\])"
                    + "(?::([0-9]{0,5}))?"
                    + "((?:/(?:" + PCT + "|[A-Za-z0-9._~!$&'()*+,;=:@-])*)*)"
                    + "(?:\\?((?:" + PCT + "|[A-Za-z0-9._~!$&'()*+,;=:@/?-])*))?"
                    + "(?:#((?:" + PCT + "|[A-Za-z0-9._~!$&'()*+,;=:@/?-])*))?");
    // decoded characters that would change the meaning of a path / query component when re-encoded
    private static final String PATH_DELIMITERS = "/?#;";
    private static final String QUERY_DELIMITERS = "&=+;#";

    /**
     * The parts of a strictly parsed absolute http(s) url. Produced only by
     * {@link SSRFChecker#parseHttpUrl(String)}; the scheme is always one of the literals "http" / "https".
     */
    public static final class HttpUrl {
        private final String scheme;
        private final String userInfo;
        private final String host;
        private final int port;
        private final String rawPath;
        private final String rawQuery;
        private final String rawFragment;

        private HttpUrl(String scheme, String userInfo, String host, int port,
                        String rawPath, String rawQuery, String rawFragment) {
            this.scheme = scheme;
            this.userInfo = userInfo;
            this.host = host;
            this.port = port;
            this.rawPath = rawPath;
            this.rawQuery = rawQuery;
            this.rawFragment = rawFragment;
        }

        /** @return the literal "http" or "https" */
        public String getScheme() {
            return scheme;
        }

        /** @return the raw userinfo, or null when absent */
        public String getRawUserInfo() {
            return userInfo;
        }

        /** @return the lower-case host (IPv6 literals keep their brackets) */
        public String getHost() {
            return host;
        }

        /** @return the port, or -1 when absent */
        public int getPort() {
            return port;
        }

        /** @return the raw (still percent-encoded) path, "" when empty */
        public String getRawPath() {
            return rawPath;
        }

        /** @return the raw (still percent-encoded) query, or null when absent */
        public String getRawQuery() {
            return rawQuery;
        }

        /** @return the raw fragment, or null when absent */
        public String getRawFragment() {
            return rawFragment;
        }
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
            logger.error(SecurityUtil.sanitizeForLog(e.toString()));
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
                    logger.error("[-] SSRF check failed. Dangerous url: " + SecurityUtil.sanitizeForLog(finalUrl));
                    return false;  // 内网ip直接return，非内网ip继续判断是否有重定向
                }

                connection = (HttpURLConnection) requireSafeUrl(finalUrl).openConnection();
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
                    logger.info("redirected url: " + SecurityUtil.sanitizeForLog(finalUrl));
                    if (i == checkTimes) {
                        return false;
                    }
                } else
                    break;
            } while (connection.getResponseCode() != HttpURLConnection.HTTP_OK);
            connection.disconnect();
        } catch (SSRFException e) {
            logger.error("[-] SSRF check failed. " + SecurityUtil.sanitizeForLog(e.getMessage()));
            return false;
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
        if (host.equals("")) {
            return true; // 异常URL当成内网IP等非法URL处理
        }

        try {
            // Every resolved address must be public; unresolvable hosts are illegal.
            resolveSafeAddresses(host);
            return false;
        } catch (SSRFException e) {
            return true;
        }
    }


    /**
     * Validate an untrusted URL before it is requested: the scheme must be http or https,
     * the host must be present and every address it resolves to must be public
     * (no loopback, link-local/metadata, private, CGNAT, multicast or configured blocked ranges).
     * Callers must also disable automatic redirects, or validate each hop.
     *
     * @param url untrusted url
     * @return the parsed, validated URL
     * @throws SSRFException if the url is not safe to request
     */
    public static URL requireSafeUrl(String url) {
        URI safe = requireSafeUri(url);
        try {
            URL parsed = safe.toURL();
            // URI and URL must agree on the host, otherwise parser differentials can bypass the check.
            if (!safe.getHost().equalsIgnoreCase(parsed.getHost())) {
                throw new SSRFException("[-] SSRF check failed. Illegal url host");
            }
            return parsed;
        } catch (SSRFException e) {
            throw e;
        } catch (Exception e) {
            throw new SSRFException("[-] SSRF check failed. Illegal url");
        }
    }


    /**
     * The single chokepoint for every outbound http(s) request of the application.
     * <ol>
     *   <li>parses the untrusted string strictly ({@link #parseHttpUrl(String)}: http/https only,
     *       RFC 3986 characters only),</li>
     *   <li>rejects userinfo ("user@host" tricks) and an empty host,</li>
     *   <li>resolves the host and rejects loopback, link-local/metadata, private and other internal
     *       addresses ({@link #resolveSafeAddresses(String)}),</li>
     *   <li>returns a <b>new</b> URI constructed from the validated components only (constant scheme
     *       literal, the resolved IP address as host, validated port, decoded path and query; fragment
     *       dropped), see {@link #buildSafeUri}. Callers must request this value, never the raw string.</li>
     * </ol>
     * Because the host is replaced by the address that was checked, the request connects to exactly
     * that address (no DNS rebinding between check and use).
     * Callers must also disable automatic redirects, or validate each hop with this method.
     *
     * @param url untrusted url
     * @return the validated, normalized URI
     * @throws SSRFException if the url is not safe to request
     */
    public static URI requireSafeUri(String url) {
        if (null == url) {
            throw new SSRFException("[-] SSRF check failed. Empty url");
        }
        HttpUrl parsed = parseHttpUrl(url.trim());
        if (null == parsed) {
            throw new SSRFException("[-] SSRF check failed. Illegal url protocol or syntax");
        }
        if (StringUtils.isEmpty(parsed.getHost()) || null != parsed.getRawUserInfo()) {
            throw new SSRFException("[-] SSRF check failed. Illegal url host");
        }
        InetAddress[] addresses = resolveSafeAddresses(parsed.getHost());
        return buildSafeUri(parsed, pinnedAddress(addresses));
    }


    /**
     * The only place where a {@link URI} is created for an outbound request. It is assembled with the
     * multi-argument constructor from components that were validated before: a constant scheme literal,
     * the resolved (public) address as host, the validated port and the decoded path and query.
     * No request string is ever handed to a URI/URL string constructor.
     */
    private static URI buildSafeUri(HttpUrl parsed, InetAddress address) {
        String scheme = "https".equals(parsed.getScheme()) ? "https" : "http";
        String host = address.getHostAddress();
        if (address instanceof Inet6Address) {
            int scope = host.indexOf('%');
            host = scope < 0 ? host : host.substring(0, scope);  // the constructor adds the brackets
        }
        try {
            return new URI(scheme, null, host, parsed.getPort(),
                    decodeComponent(parsed.getRawPath(), PATH_DELIMITERS),
                    decodeComponent(parsed.getRawQuery(), QUERY_DELIMITERS), null);
        } catch (URISyntaxException e) {
            throw new SSRFException("[-] SSRF check failed. Illegal url");
        }
    }


    /**
     * Percent-decode a path or query. Only printable ASCII (and space) may be encoded, and delimiters
     * that would change the meaning of the component once decoded are rejected. The URI constructor
     * re-encodes everything that needs it.
     */
    private static String decodeComponent(String raw, String forbidden) {
        if (null == raw) {
            return null;
        }
        StringBuilder sb = new StringBuilder(raw.length());
        for (int i = 0; i < raw.length(); i++) {
            char ch = raw.charAt(i);
            if (ch != '%') {
                sb.append(ch);
                continue;
            }
            int value = Integer.parseInt(raw.substring(i + 1, i + 3), 16);  // shape guaranteed by the pattern
            i += 2;
            if (value < 0x20 || value > 0x7e || forbidden.indexOf(value) >= 0) {
                throw new SSRFException("[-] SSRF check failed. Illegal encoded character in url");
            }
            sb.append((char) value);
        }
        return sb.toString();
    }


    /**
     * Pick the address a request is pinned to: the first IPv4 address, otherwise the first address.
     * The addresses must come from {@link #resolveSafeAddresses(String)}.
     */
    private static InetAddress pinnedAddress(InetAddress[] addresses) {
        for (InetAddress address : addresses) {
            if (address instanceof Inet4Address) {
                return address;
            }
        }
        return addresses[0];
    }


    /**
     * Host literal of the pinned validated address, usable inside a url: dotted IPv4, or the IPv6
     * address in brackets (without scope id).
     *
     * @param addresses addresses returned by {@link #resolveSafeAddresses(String)}
     */
    public static String pinnedHostLiteral(InetAddress[] addresses) {
        InetAddress pinned = pinnedAddress(addresses);
        String host = pinned.getHostAddress();
        if (pinned instanceof Inet6Address) {
            int scope = host.indexOf('%');
            return "[" + (scope < 0 ? host : host.substring(0, scope)) + "]";
        }
        return host;
    }


    /**
     * Strictly parse an absolute http/https url with a RFC 3986 regular expression. No {@link URI} or
     * {@link URL} is created from the string and no network access happens here.
     *
     * @param url untrusted url
     * @return the parsed parts, or null when it is not a well-formed absolute http(s) url
     */
    public static HttpUrl parseHttpUrl(String url) {
        if (null == url) {
            return null;
        }
        Matcher m = HTTP_URL_PATTERN.matcher(url);
        if (!m.matches()) {
            return null;
        }
        int port = -1;
        if (null != m.group(4) && !m.group(4).isEmpty()) {
            port = Integer.parseInt(m.group(4));
            if (port < 1 || port > 65535) {
                return null;
            }
        }
        String scheme = "https".equalsIgnoreCase(m.group(1)) ? "https" : "http";
        return new HttpUrl(scheme, m.group(2), m.group(3).toLowerCase(java.util.Locale.ROOT), port,
                m.group(5), m.group(6), m.group(7));
    }


    /**
     * Resolve a host and make sure all of its addresses are public.
     * The returned addresses are the validated ones and may be used to pin the connection.
     *
     * @param host host name or ip literal
     * @return validated addresses
     * @throws SSRFException if the host cannot be resolved or any address is not public
     */
    public static InetAddress[] resolveSafeAddresses(String host) {
        if (StringUtils.isEmpty(host)) {
            throw new SSRFException("[-] SSRF check failed. Empty host");
        }
        // Octal ip notation (012.0.0.1) is converted to decimal first, see host2ip.
        String lookupHost = isOctalIP(host) ? decimalIp : host;
        InetAddress[] addresses;
        try {
            addresses = InetAddress.getAllByName(lookupHost);
        } catch (Exception e) {
            throw new SSRFException("[-] SSRF check failed. Host cannot be resolved");
        }
        for (InetAddress address : addresses) {
            if (isBlockedAddress(address)) {
                throw new SSRFException("[-] SSRF check failed. Internal host");
            }
        }
        return addresses;
    }


    /**
     * Whether an address is loopback, link-local (cloud metadata), private, CGNAT, multicast,
     * unspecified, IPv6 unique-local or in the configured blocked subnets.
     */
    public static boolean isBlockedAddress(InetAddress address) {
        if (address.isAnyLocalAddress() || address.isLoopbackAddress() || address.isLinkLocalAddress()
                || address.isSiteLocalAddress() || address.isMulticastAddress()) {
            return true;
        }
        byte[] raw = address.getAddress();
        if (raw.length == 4) {
            int first = raw[0] & 0xff;
            int second = raw[1] & 0xff;
            // 0.0.0.0/8 and 100.64.0.0/10 (carrier-grade NAT, e.g. Alibaba metadata 100.100.100.200)
            if (first == 0 || (first == 100 && second >= 64 && second <= 127)) {
                return true;
            }
            return isInternalIp(address.getHostAddress());
        }
        // fc00::/7 unique local addresses
        return raw.length == 16 && (raw[0] & 0xfe) == 0xfc;
    }


    /**
     * 使用SubnetUtils库判断ip是否在内网网段
     *
     * @param strIP ip字符串
     * @return 如果是内网ip，返回true，否则返回false。
     */
    public static boolean isInternalIp(String strIP) {
        if (StringUtils.isEmpty(strIP)) {
            logger.error("[-] SSRF check failed. IP is empty. " + SecurityUtil.sanitizeForLog(strIP));
            return true;
        }

        ArrayList<String> blackSubnets = WebConfig.getSsrfBlockIps();
        for (String subnet : blackSubnets) {
            SubnetUtils utils = new SubnetUtils(subnet);
            if (utils.getInfo().isInRange(strIP)) {
                logger.error("[-] SSRF check failed. Internal IP: " + SecurityUtil.sanitizeForLog(strIP));
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
            logger.error("host2ip exception " + SecurityUtil.sanitizeForLog(e.getMessage()));
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
                    logger.error("Illegal ipv4: " + SecurityUtil.sanitizeForLog(host));
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
                        logger.error("Illegal ipv4: " + SecurityUtil.sanitizeForLog(host));
                        return false;
                    }
                    // start with "0", but not "0"
                    if (ip.startsWith("0") && !ip.equals("0")) {
                        if (Integer.valueOf(ip, 8) >= 256){
                            logger.error("Illegal ipv4: " + SecurityUtil.sanitizeForLog(host));
                            return false;
                        }
                        newDecimalIP.append(Integer.valueOf(ip, 8)).append(".");
                        is_octal = true;
                    }else{
                        if (Integer.valueOf(ip, 10) >= 256) {
                            logger.error("Illegal ipv4: " + SecurityUtil.sanitizeForLog(host));
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
            logger.error("SSRFChecker isOctalIP exception: " + SecurityUtil.sanitizeForLog(e.getMessage()));
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
        HttpUrl parsed = parseHttpUrl(url);
        if (null == parsed) {
            return "";
        }
        return parsed.getHost();
    }

}
