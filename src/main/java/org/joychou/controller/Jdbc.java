package org.joychou.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.net.InetAddress;
import java.net.URI;
import java.sql.DriverManager;
import java.util.Arrays;
import java.util.List;

/**
 * Jdbc Attack @2023.04
 */
@Slf4j
@RestController
@RequestMapping("/jdbc")
public class Jdbc {

    private static final List<String> ALLOWED_JDBC_HOSTS = Arrays.asList("127.0.0.1", "localhost");

    /**
     * Validate JDBC URL to prevent SSRF via attacker-controlled connection strings.
     * Only allows connections to explicitly permitted hosts.
     */
    private static boolean isJdbcUrlSafe(String jdbcUrl) {
        if (jdbcUrl == null) {
            return false;
        }
        try {
            // JDBC URLs use format jdbc:subprotocol://host:port/database
            // Extract the part after "jdbc:<subprotocol>://"
            if (!jdbcUrl.startsWith("jdbc:")) {
                return false;
            }
            String withoutJdbc = jdbcUrl.substring(5); // remove "jdbc:"
            int schemeEnd = withoutJdbc.indexOf("://");
            if (schemeEnd < 0) {
                return false;
            }
            String afterScheme = withoutJdbc.substring(schemeEnd + 3);
            // Parse as a URI to extract host
            URI uri = new URI("db://" + afterScheme);
            String host = uri.getHost();
            if (host == null || host.isEmpty()) {
                return false;
            }
            // Resolve DNS and check that the IP is not internal/private
            InetAddress addr = InetAddress.getByName(host);
            if (addr.isLoopbackAddress() || addr.isLinkLocalAddress()
                    || addr.isSiteLocalAddress() || addr.isAnyLocalAddress()) {
                // Only allow if the host is in the explicit allowlist
                if (!ALLOWED_JDBC_HOSTS.contains(host.toLowerCase())) {
                    return false;
                }
            }
            return true;
        } catch (Exception e) {
            log.error("JDBC URL validation failed");
            return false;
        }
    }

    /**
     * <a href="https://github.com/JoyChou93/java-sec-code/wiki/CVE-2022-21724">CVE-2022-21724</a>
     */
    @RequestMapping("/postgresql")
    public String postgresql(String jdbcUrlBase64) throws Exception{
        byte[] b = java.util.Base64.getDecoder().decode(jdbcUrlBase64);
        String jdbcUrl = new String(b);
        if (!isJdbcUrlSafe(jdbcUrl)) {
            return "JDBC URL validation failed";
        }
        log.info("Connecting to PostgreSQL via JDBC");
        DriverManager.getConnection(jdbcUrl);
        return "OK";
    }

    @RequestMapping("/db2")
    public String db2(String jdbcUrlBase64) throws Exception{
        Class.forName("com.ibm.db2.jcc.DB2Driver");
        byte[] b = java.util.Base64.getDecoder().decode(jdbcUrlBase64);
        String jdbcUrl = new String(b);
        if (!isJdbcUrlSafe(jdbcUrl)) {
            return "JDBC URL validation failed";
        }
        log.info("Connecting to DB2 via JDBC");
        DriverManager.getConnection(jdbcUrl);
        return "OK";
    }
}
