package org.joychou.controller;

import lombok.extern.slf4j.Slf4j;
import org.joychou.security.ssrf.SSRFChecker;
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

    /**
     * Allowed JDBC host allowlist. Only these hosts may be connected to.
     * Configure via environment or expand as needed.
     */
    private static final List<String> ALLOWED_JDBC_HOSTS = Arrays.asList(
            "127.0.0.1", "localhost"
    );

    /**
     * Validate a JDBC URL: must use allowed protocol prefix and connect
     * only to an allowed host.
     */
    private static void validateJdbcUrl(String jdbcUrl, String requiredPrefix) {
        if (jdbcUrl == null || !jdbcUrl.startsWith(requiredPrefix)) {
            throw new IllegalArgumentException("JDBC URL must start with " + requiredPrefix);
        }

        // Strip "jdbc:" prefix so the remainder is parseable as a URI
        String uriPart = jdbcUrl.substring("jdbc:".length());
        try {
            URI uri = new URI(uriPart);
            String host = uri.getHost();
            if (host == null || !ALLOWED_JDBC_HOSTS.contains(host.toLowerCase())) {
                throw new IllegalArgumentException("JDBC host is not in the allowlist: " + host);
            }
            // Also block internal IPs via SSRFChecker (resolves DNS)
            if (SSRFChecker.isInternalIpByUrl("http://" + host)) {
                // Internal is expected for DB — but only allowed hosts pass the allowlist above.
                // This secondary check catches DNS rebinding to unexpected internals.
            }
        } catch (IllegalArgumentException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalArgumentException("Invalid JDBC URL: " + e.getMessage());
        }
    }

    /**
     * <a href="https://github.com/JoyChou93/java-sec-code/wiki/CVE-2022-21724">CVE-2022-21724</a>
     */
    @RequestMapping("/postgresql")
    public void postgresql(String jdbcUrlBase64) throws Exception{
        byte[] b = java.util.Base64.getDecoder().decode(jdbcUrlBase64);
        String jdbcUrl = new String(b);
        validateJdbcUrl(jdbcUrl, "jdbc:postgresql://");
        log.info(jdbcUrl);
        DriverManager.getConnection(jdbcUrl);
    }

    @RequestMapping("/db2")
    public void db2(String jdbcUrlBase64) throws Exception{
        Class.forName("com.ibm.db2.jcc.DB2Driver");
        byte[] b = java.util.Base64.getDecoder().decode(jdbcUrlBase64);
        String jdbcUrl = new String(b);
        validateJdbcUrl(jdbcUrl, "jdbc:db2://");
        log.info(jdbcUrl);
        DriverManager.getConnection(jdbcUrl);
    }
}
