package org.joychou.controller;

import lombok.extern.slf4j.Slf4j;
import org.joychou.security.ssrf.SSRFChecker;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.net.URI;
import java.sql.DriverManager;

/**
 * Jdbc Attack @2023.04
 */
@Slf4j
@RestController
@RequestMapping("/jdbc")
public class Jdbc {

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

    /**
     * Validate JDBC URL to prevent SSRF. Extracts the host from the JDBC URL
     * and checks if it resolves to a private/internal IP address.
     */
    private void validateJdbcUrl(String jdbcUrl) throws Exception {
        // JDBC URLs are of the form jdbc:subprotocol://host:port/database
        // Strip the "jdbc:" prefix to parse as a normal URI
        if (jdbcUrl == null || !jdbcUrl.startsWith("jdbc:")) {
            throw new IllegalArgumentException("Invalid JDBC URL");
        }
        String uriPart = jdbcUrl.substring(5); // remove "jdbc:"
        // Handle sub-protocol prefix like "postgresql:" or "db2:"
        int schemeEnd = uriPart.indexOf("://");
        if (schemeEnd < 0) {
            throw new IllegalArgumentException("Invalid JDBC URL format");
        }
        // Build a parseable URL: use http:// as scheme for host extraction
        String httpUrl = "http" + uriPart.substring(schemeEnd);
        try {
            URI uri = new URI(httpUrl);
            String host = uri.getHost();
            if (host == null || host.isEmpty()) {
                throw new IllegalArgumentException("Cannot extract host from JDBC URL");
            }
            if (SSRFChecker.isInternalIpByUrl("http://" + host + "/")) {
                throw new IllegalArgumentException("JDBC URL resolves to internal/private IP");
            }
        } catch (IllegalArgumentException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalArgumentException("Invalid JDBC URL: " + e.getMessage());
        }
    }
}
