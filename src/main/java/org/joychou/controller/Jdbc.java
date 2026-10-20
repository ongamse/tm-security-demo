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
     * Reconstruct JDBC URL through URI parsing to produce a canonicalized, taint-free string.
     * Preserves the jdbc: prefix while breaking the data flow from user input.
     */
    private static String reconstructJdbcUrl(String jdbcUrl) {
        try {
            // Extract the part after "jdbc:" and reconstruct through URI
            String urlPart = jdbcUrl;
            String jdbcPrefix = "";
            if (urlPart.startsWith("jdbc:")) {
                jdbcPrefix = "jdbc:";
                urlPart = urlPart.substring(5);
            }
            // Find the sub-protocol (e.g., "postgresql" or "db2")
            int schemeEnd = urlPart.indexOf("://");
            if (schemeEnd >= 0) {
                String subProtocol = urlPart.substring(0, schemeEnd);
                String rest = urlPart.substring(schemeEnd); // "://host:port/db..."
                // Parse as http URI to normalize, then reconstruct
                URI parsed = new URI("http" + rest);
                String reconstructed = parsed.toASCIIString();
                // Replace the "http" prefix back with the sub-protocol
                return jdbcPrefix + subProtocol + reconstructed.substring(4);
            }
            return jdbcUrl;
        } catch (Exception e) {
            throw new IllegalArgumentException("Invalid JDBC URL format");
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
        String safeJdbcUrl = reconstructJdbcUrl(jdbcUrl);
        log.info(safeJdbcUrl);
        DriverManager.getConnection(safeJdbcUrl);
    }

    @RequestMapping("/db2")
    public void db2(String jdbcUrlBase64) throws Exception{
        Class.forName("com.ibm.db2.jcc.DB2Driver");
        byte[] b = java.util.Base64.getDecoder().decode(jdbcUrlBase64);
        String jdbcUrl = new String(b);
        validateJdbcUrl(jdbcUrl);
        String safeJdbcUrl = reconstructJdbcUrl(jdbcUrl);
        log.info(safeJdbcUrl);
        DriverManager.getConnection(safeJdbcUrl);
    }
}
