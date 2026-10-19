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

    private static final List<String> ALLOWED_JDBC_HOSTS = Arrays.asList(
        // Add allowed database hosts here
    );

    /**
     * Validate that a JDBC URL does not target an internal/private IP address.
     * Extracts host from jdbc:subprotocol://host:port/... format.
     */
    private static void validateJdbcUrl(String jdbcUrl) throws Exception {
        if (jdbcUrl == null) {
            throw new IllegalArgumentException("JDBC URL must not be null");
        }
        // Extract the host portion from the JDBC URL (jdbc:postgresql://host:port/db)
        String urlPart = jdbcUrl;
        if (urlPart.startsWith("jdbc:")) {
            urlPart = urlPart.substring(5); // remove "jdbc:"
        }
        // Remove subprotocol prefix (e.g., "postgresql:" or "db2:")
        int schemeEnd = urlPart.indexOf("://");
        if (schemeEnd >= 0) {
            urlPart = urlPart.substring(schemeEnd); // keep "://host:port/db"
        }
        // Parse as a URI to extract host
        URI uri = new URI("http" + urlPart);
        String host = uri.getHost();
        if (host == null || host.isEmpty()) {
            throw new IllegalArgumentException("Cannot extract host from JDBC URL");
        }
        // Resolve hostname to IP and reject internal/private addresses
        InetAddress addr = InetAddress.getByName(host);
        if (addr.isLoopbackAddress() || addr.isLinkLocalAddress()
                || addr.isSiteLocalAddress() || addr.isAnyLocalAddress()) {
            throw new IllegalArgumentException("JDBC URL targets an internal/private IP address");
        }
        // Additionally check allowlist if configured
        if (!ALLOWED_JDBC_HOSTS.isEmpty() && !ALLOWED_JDBC_HOSTS.contains(host)) {
            throw new IllegalArgumentException("JDBC host not in allowlist: " + host);
        }
    }

    /**
     * <a href="https://github.com/JoyChou93/java-sec-code/wiki/CVE-2022-21724">CVE-2022-21724</a>
     */
    @RequestMapping("/postgresql")
    public void postgresql(String jdbcUrlBase64) throws Exception{
        byte[] b = java.util.Base64.getDecoder().decode(jdbcUrlBase64);
        String jdbcUrl = new String(b);
        validateJdbcUrl(jdbcUrl);
        log.info(jdbcUrl);
        DriverManager.getConnection(jdbcUrl);
    }

    @RequestMapping("/db2")
    public void db2(String jdbcUrlBase64) throws Exception{
        Class.forName("com.ibm.db2.jcc.DB2Driver");
        byte[] b = java.util.Base64.getDecoder().decode(jdbcUrlBase64);
        String jdbcUrl = new String(b);
        validateJdbcUrl(jdbcUrl);
        log.info(jdbcUrl);
        DriverManager.getConnection(jdbcUrl);
    }
}
