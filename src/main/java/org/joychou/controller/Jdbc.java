package org.joychou.controller;

import lombok.extern.slf4j.Slf4j;
import org.joychou.security.ssrf.SSRFChecker;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.sql.DriverManager;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/**
 * Jdbc Attack @2023.04
 */
@Slf4j
@RestController
@RequestMapping("/jdbc")
public class Jdbc {

    // Allowlisted JDBC sub-protocols to prevent arbitrary driver loading
    private static final Set<String> ALLOWED_JDBC_TYPES = new HashSet<>(
            Arrays.asList("postgresql", "db2")
    );

    /**
     * Validate JDBC URL: only allowed sub-protocols and block internal/private IPs.
     */
    private void validateJdbcUrl(String jdbcUrl) throws Exception {
        if (jdbcUrl == null || !jdbcUrl.startsWith("jdbc:")) {
            throw new IllegalArgumentException("Invalid JDBC URL: must start with jdbc:");
        }

        // Extract JDBC sub-protocol (e.g., "postgresql" from "jdbc:postgresql://host/db")
        String withoutJdbc = jdbcUrl.substring(5); // strip "jdbc:"
        int colonIdx = withoutJdbc.indexOf(':');
        if (colonIdx < 0) {
            throw new IllegalArgumentException("Invalid JDBC URL: missing sub-protocol");
        }
        String subProtocol = withoutJdbc.substring(0, colonIdx).toLowerCase();
        if (!ALLOWED_JDBC_TYPES.contains(subProtocol)) {
            throw new IllegalArgumentException("Blocked JDBC sub-protocol: " + subProtocol);
        }

        // Extract host from the JDBC URL and verify it is not an internal IP
        String remainder = withoutJdbc.substring(colonIdx + 1);
        // Handle //host:port/db format
        if (remainder.startsWith("//")) {
            String hostPart = remainder.substring(2);
            // Remove path component
            int slashIdx = hostPart.indexOf('/');
            if (slashIdx >= 0) {
                hostPart = hostPart.substring(0, slashIdx);
            }
            // Remove port
            int portIdx = hostPart.lastIndexOf(':');
            if (portIdx >= 0) {
                hostPart = hostPart.substring(0, portIdx);
            }
            // Remove user info
            int atIdx = hostPart.indexOf('@');
            if (atIdx >= 0) {
                hostPart = hostPart.substring(atIdx + 1);
            }
            if (hostPart.isEmpty()) {
                throw new IllegalArgumentException("Invalid JDBC URL: missing host");
            }
            // Check via SSRFChecker (constructs a synthetic http URL for IP resolution)
            String syntheticUrl = "http://" + hostPart;
            if (SSRFChecker.isInternalIpByUrl(syntheticUrl)) {
                throw new IllegalArgumentException("Blocked: JDBC URL host resolves to an internal IP address");
            }
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
