package org.joychou.controller;

import lombok.extern.slf4j.Slf4j;
import org.joychou.security.SecurityUtil;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.net.Inet6Address;
import java.net.InetAddress;
import java.sql.DriverManager;

/**
 * Jdbc Attack @2023.04
 */
@Slf4j
@RestController
@RequestMapping("/jdbc")
public class Jdbc {

    private static final int[] POSTGRESQL_PORTS = {5432};
    private static final int[] DB2_PORTS = {50000, 50001};

    /**
     * <a href="https://github.com/JoyChou93/java-sec-code/wiki/CVE-2022-21724">CVE-2022-21724</a>
     */
    @RequestMapping("/postgresql")
    public void postgresql(String jdbcUrlBase64) throws Exception{
        byte[] b = java.util.Base64.getDecoder().decode(jdbcUrlBase64);
        String jdbcUrl = checkJdbcUrl(new String(b, java.nio.charset.StandardCharsets.UTF_8), "jdbc:postgresql://", POSTGRESQL_PORTS);
        log.info("jdbc postgresql connect");
        DriverManager.getConnection(jdbcUrl);
    }

    @RequestMapping("/db2")
    public void db2(String jdbcUrlBase64) throws Exception{
        Class.forName("com.ibm.db2.jcc.DB2Driver");
        byte[] b = java.util.Base64.getDecoder().decode(jdbcUrlBase64);
        String jdbcUrl = checkJdbcUrl(new String(b, java.nio.charset.StandardCharsets.UTF_8), "jdbc:db2://", DB2_PORTS);
        log.info("jdbc db2 connect");
        DriverManager.getConnection(jdbcUrl);
    }

    private static final java.util.regex.Pattern JDBC_TARGET_PATTERN = java.util.regex.Pattern.compile(
            "(\\[[0-9A-Fa-f:]{2,45}\\]|[A-Za-z0-9.-]{1,253})(?::([0-9]{1,5}))?(?:/([A-Za-z0-9_]{1,64}))?");
    private static final String DB_NAME_ALPHABET =
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_";

    /**
     * Rebuild a JDBC url from validated pieces only. The user supplied url selects values, it is never
     * passed to the driver: the result is a fixed driver prefix, a host that is a well formed
     * host name / ip literal and resolves exclusively to public addresses (written as the resolved
     * ip so the driver does not resolve the name a second time), an allowlisted port and a database
     * name made of [A-Za-z0-9_] only. User info and driver properties (query string, ';' properties
     * such as socketFactory / sslfactory, which make the driver instantiate arbitrary classes) are
     * not representable in the pattern.
     *
     * @param jdbcUrl url decoded from the request
     * @param prefix  allowed driver prefix, e.g. jdbc:postgresql://
     * @param ports   allowlisted ports, the first one is used when the url has no port
     * @return the rebuilt url
     * @throws IllegalArgumentException if the url is not allowed
     */
    private static String checkJdbcUrl(String jdbcUrl, String prefix, int[] ports) {
        if (jdbcUrl == null || !jdbcUrl.startsWith(prefix)) {
            throw new IllegalArgumentException("Illegal jdbc url");
        }
        java.util.regex.Matcher m = JDBC_TARGET_PATTERN.matcher(jdbcUrl.substring(prefix.length()));
        if (!m.matches()) {
            throw new IllegalArgumentException("Illegal jdbc url");
        }
        String rawHost = m.group(1);
        if (rawHost.startsWith("[")) {
            rawHost = rawHost.substring(1, rawHost.length() - 1);
        }
        String host = SecurityUtil.parseBareHost(rawHost);
        InetAddress address = host == null ? null : SecurityUtil.resolvePublicAddress(host);
        if (address == null) {
            throw new IllegalArgumentException("Illegal jdbc url");
        }
        int port = ports[0];
        if (m.group(2) != null) {
            port = Integer.parseInt(m.group(2));
            boolean allowed = false;
            for (int p : ports) {
                allowed |= p == port;
            }
            if (!allowed) {
                throw new IllegalArgumentException("Illegal jdbc url");
            }
        }
        String ip = address.getHostAddress();
        if (address instanceof Inet6Address) {
            ip = "[" + ip + "]";
        }
        StringBuilder rebuilt = new StringBuilder(prefix).append(ip).append(':').append(port);
        if (m.group(3) != null) {
            String db = m.group(3);
            rebuilt.append('/');
            for (int i = 0; i < db.length(); i++) {
                rebuilt.append(DB_NAME_ALPHABET.charAt(DB_NAME_ALPHABET.indexOf(db.charAt(i))));
            }
        }
        return rebuilt.toString();
    }
}
