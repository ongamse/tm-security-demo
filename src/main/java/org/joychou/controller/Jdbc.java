package org.joychou.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

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

    // Allowlist of permitted JDBC hosts to prevent SSRF via JDBC connections
    private static final List<String> ALLOWED_JDBC_HOSTS = Arrays.asList("127.0.0.1", "localhost");

    /**
     * Validate that the JDBC URL targets only allowed hosts.
     * Blocks SSRF via arbitrary JDBC connection strings.
     */
    private static void validateJdbcUrl(String jdbcUrl) throws Exception {
        if (jdbcUrl == null || jdbcUrl.isEmpty()) {
            throw new SecurityException("JDBC URL must not be empty");
        }
        // JDBC URLs are typically jdbc:subprotocol://host:port/database
        // Strip "jdbc:" prefix to parse the remainder as a URI
        String urlPart = jdbcUrl;
        if (urlPart.startsWith("jdbc:")) {
            urlPart = urlPart.substring(5);
        }
        // Strip sub-protocol prefix (e.g., "postgresql://", "db2://")
        int schemeEnd = urlPart.indexOf("://");
        if (schemeEnd < 0) {
            throw new SecurityException("Invalid JDBC URL format");
        }
        // Replace sub-protocol with http so URI can parse the host
        String asHttp = "http" + urlPart.substring(schemeEnd);
        URI uri = new URI(asHttp);
        String host = uri.getHost();
        if (host == null || host.isEmpty()) {
            throw new SecurityException("Could not parse host from JDBC URL");
        }
        if (!ALLOWED_JDBC_HOSTS.contains(host.toLowerCase())) {
            throw new SecurityException("JDBC connection to host '" + host + "' is not allowed");
        }
    }

    /**
     * <a href="https://github.com/JoyChou93/java-sec-code/wiki/CVE-2022-21724">CVE-2022-21724</a>
     */
    @RequestMapping("/postgresql")
    public void postgresql(String jdbcUrlBase64) throws Exception{
        byte[] b = java.util.Base64.getDecoder().decode(jdbcUrlBase64);
        String jdbcUrl = new String(b);
        log.info(jdbcUrl);
        validateJdbcUrl(jdbcUrl);
        DriverManager.getConnection(jdbcUrl);
    }

    @RequestMapping("/db2")
    public void db2(String jdbcUrlBase64) throws Exception{
        Class.forName("com.ibm.db2.jcc.DB2Driver");
        byte[] b = java.util.Base64.getDecoder().decode(jdbcUrlBase64);
        String jdbcUrl = new String(b);
        log.info(jdbcUrl);
        validateJdbcUrl(jdbcUrl);
        DriverManager.getConnection(jdbcUrl);
    }
}
