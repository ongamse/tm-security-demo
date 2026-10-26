package org.joychou.controller;

import lombok.extern.slf4j.Slf4j;
import org.joychou.security.ssrf.SSRFChecker;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.net.URI;
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

    // Allowlist of permitted JDBC host:port targets
    private static final Set<String> ALLOWED_JDBC_HOSTS = new HashSet<>(Arrays.asList(
            "localhost:5432", "localhost:50000",
            "127.0.0.1:5432", "127.0.0.1:50000"
    ));

    /**
     * Validate a JDBC URL: extract the host and reject connections to internal/non-allowlisted hosts.
     *
     * @param jdbcUrl the JDBC connection URL
     * @throws SecurityException if the URL targets a disallowed host
     */
    private void validateJdbcUrl(String jdbcUrl) {
        if (jdbcUrl == null) {
            throw new SecurityException("JDBC URL must not be null");
        }
        try {
            // Strip the "jdbc:" prefix so the remainder can be parsed as a URI
            String uriPart = jdbcUrl;
            if (uriPart.startsWith("jdbc:")) {
                uriPart = uriPart.substring(5);
            }
            // Handle sub-protocol prefix like "postgresql:" or "db2:"
            int schemeEnd = uriPart.indexOf("://");
            if (schemeEnd < 0) {
                throw new SecurityException("JDBC URL rejected: cannot parse host from URL");
            }

            URI uri = new URI(uriPart);
            String host = uri.getHost();
            int port = uri.getPort();

            if (host == null) {
                throw new SecurityException("JDBC URL rejected: no host found");
            }

            String hostPort = host + (port > 0 ? ":" + port : "");

            // Check against allowlist
            if (!ALLOWED_JDBC_HOSTS.contains(hostPort)) {
                throw new SecurityException("JDBC URL rejected: host not in allowlist: " + hostPort);
            }

            // Additionally reject if the resolved IP is internal (defends against DNS rebinding)
            String ip = SSRFChecker.host2ip(host);
            if (ip.isEmpty() || SSRFChecker.isInternalIp(ip)) {
                // For JDBC, connections to localhost are expected; only block non-allowlisted internal
                if (!ALLOWED_JDBC_HOSTS.contains(hostPort)) {
                    throw new SecurityException("JDBC URL rejected: host resolves to internal IP");
                }
            }
        } catch (SecurityException e) {
            throw e;
        } catch (Exception e) {
            throw new SecurityException("JDBC URL rejected: cannot validate URL: " + e.getMessage());
        }
    }

    /**
     * <a href="https://github.com/JoyChou93/java-sec-code/wiki/CVE-2022-21724">CVE-2022-21724</a>
     */
    @RequestMapping("/postgresql")
    public ResponseEntity<String> postgresql(String jdbcUrlBase64) throws Exception {
        byte[] b = java.util.Base64.getDecoder().decode(jdbcUrlBase64);
        String jdbcUrl = new String(b);
        log.info(jdbcUrl);
        try {
            validateJdbcUrl(jdbcUrl);
        } catch (SecurityException e) {
            log.error("JDBC SSRF rejected: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(e.getMessage());
        }
        DriverManager.getConnection(jdbcUrl);
        return ResponseEntity.ok("OK");
    }

    @RequestMapping("/db2")
    public ResponseEntity<String> db2(String jdbcUrlBase64) throws Exception {
        Class.forName("com.ibm.db2.jcc.DB2Driver");
        byte[] b = java.util.Base64.getDecoder().decode(jdbcUrlBase64);
        String jdbcUrl = new String(b);
        log.info(jdbcUrl);
        try {
            validateJdbcUrl(jdbcUrl);
        } catch (SecurityException e) {
            log.error("JDBC SSRF rejected: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(e.getMessage());
        }
        DriverManager.getConnection(jdbcUrl);
        return ResponseEntity.ok("OK");
    }
}
