package org.joychou.controller;

import lombok.extern.slf4j.Slf4j;
import org.joychou.security.SecurityUtil;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.sql.DriverManager;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Jdbc Attack @2023.04
 */
@Slf4j
@RestController
@RequestMapping("/jdbc")
public class Jdbc {

    /**
     * Strict JDBC URL shape: fixed subprotocol, plain host[:port][/database]. Connection
     * properties (query string, ';' or ':' property lists such as socketFactory,
     * loggerFile, clientRerouteServerListJNDIName ...) are rejected.
     */
    private static final Pattern POSTGRESQL_URL =
            Pattern.compile("^jdbc:postgresql://([A-Za-z0-9.-]{1,253})(?::(\\d{1,5}))?(?:/([A-Za-z0-9_.-]{1,63}))?$");
    private static final Pattern DB2_URL =
            Pattern.compile("^jdbc:db2://([A-Za-z0-9.-]{1,253})(?::(\\d{1,5}))?(?:/([A-Za-z0-9_.-]{1,63}))?$");

    /**
     * Decode and validate the user supplied JDBC URL: allowlisted subprotocol, no connection
     * properties, and a host that only resolves to public addresses. The host is resolved exactly
     * once and replaced by the validated IP literal in the returned URL, so the driver connects to the
     * address that was checked and a DNS-rebinding answer cannot swap in an internal address.
     */
    private static String checkedJdbcUrl(String jdbcUrlBase64, Pattern allowed) {
        if (jdbcUrlBase64 == null) {
            throw new IllegalArgumentException("Illegal jdbc url");
        }
        String jdbcUrl;
        try {
            jdbcUrl = new String(java.util.Base64.getDecoder().decode(jdbcUrlBase64), StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Illegal jdbc url");
        }
        Matcher m = allowed.matcher(jdbcUrl);
        if (!m.matches()) {
            throw new IllegalArgumentException("Illegal jdbc url");
        }
        InetAddress[] addrs = SecurityUtil.resolveSafeOutboundHost(m.group(1));
        if (addrs == null) {
            throw new IllegalArgumentException("Illegal jdbc url");
        }
        InetAddress pinned = addrs[0];
        for (InetAddress a : addrs) {
            if (a instanceof Inet4Address) {
                pinned = a;
                break;
            }
        }
        String hostLiteral = pinned.getHostAddress();
        int scope = hostLiteral.indexOf('%');
        if (scope >= 0) {
            hostLiteral = hostLiteral.substring(0, scope);
        }
        if (pinned instanceof Inet6Address) {
            hostLiteral = "[" + hostLiteral + "]";
        }
        String subprotocol = jdbcUrl.substring(0, jdbcUrl.indexOf("//") + 2);
        StringBuilder pinnedUrl = new StringBuilder(subprotocol).append(hostLiteral);
        if (m.group(2) != null) {
            pinnedUrl.append(':').append(m.group(2));
        }
        if (m.group(3) != null) {
            pinnedUrl.append('/').append(m.group(3));
        }
        return pinnedUrl.toString();
    }

    /**
     * <a href="https://github.com/JoyChou93/java-sec-code/wiki/CVE-2022-21724">CVE-2022-21724</a>
     */
    @RequestMapping("/postgresql")
    public void postgresql(String jdbcUrlBase64) throws Exception{
        String jdbcUrl = checkedJdbcUrl(jdbcUrlBase64, POSTGRESQL_URL);
        log.info(jdbcUrl);
        DriverManager.getConnection(jdbcUrl);
    }

    @RequestMapping("/db2")
    public void db2(String jdbcUrlBase64) throws Exception{
        Class.forName("com.ibm.db2.jcc.DB2Driver");
        String jdbcUrl = checkedJdbcUrl(jdbcUrlBase64, DB2_URL);
        log.info(jdbcUrl);
        DriverManager.getConnection(jdbcUrl);
    }
}
