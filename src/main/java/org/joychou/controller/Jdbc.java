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
import java.util.List;

/**
 * Jdbc Attack @2023.04
 */
@Slf4j
@RestController
@RequestMapping("/jdbc")
public class Jdbc {

    private static final List<String> ALLOWED_JDBC_HOSTS = Arrays.asList(
            "localhost", "127.0.0.1"
    );

    /**
     * Validate JDBC URL to prevent SSRF via attacker-controlled JDBC connection strings.
     * Only allows connections to explicitly allowlisted hosts.
     */
    private static boolean isJdbcUrlSafe(String jdbcUrl) {
        if (jdbcUrl == null || jdbcUrl.isEmpty()) {
            return false;
        }
        try {
            // Extract the host portion from the JDBC URL
            // JDBC URLs have the form jdbc:subprotocol://host:port/database
            String urlPart = jdbcUrl;
            if (urlPart.startsWith("jdbc:")) {
                // Remove "jdbc:" prefix and the subprotocol to get to the //host part
                int doubleSlash = urlPart.indexOf("//");
                if (doubleSlash < 0) {
                    return false;
                }
                urlPart = urlPart.substring(doubleSlash);
            }
            // Parse as a URI to extract the host
            URI uri = new URI("http:" + urlPart);
            String host = uri.getHost();
            if (host == null || host.isEmpty()) {
                return false;
            }
            host = host.toLowerCase();
            // Only allow explicitly allowlisted hosts
            if (!ALLOWED_JDBC_HOSTS.contains(host)) {
                return false;
            }
            // Also verify resolved IP is not an internal address (beyond localhost)
            if (SSRFChecker.isInternalIp(host) && !"127.0.0.1".equals(host) && !"localhost".equals(host)) {
                return false;
            }
            return true;
        } catch (Exception e) {
            log.error("JDBC URL validation failed: " + e.getMessage());
            return false;
        }
    }

    /**
     * <a href="https://github.com/JoyChou93/java-sec-code/wiki/CVE-2022-21724">CVE-2022-21724</a>
     */
    @RequestMapping("/postgresql")
    public ResponseEntity<String> postgresql(String jdbcUrlBase64) throws Exception{
        byte[] b = java.util.Base64.getDecoder().decode(jdbcUrlBase64);
        String jdbcUrl = new String(b);
        if (!isJdbcUrlSafe(jdbcUrl)) {
            log.error("JDBC SSRF check failed for postgresql connection");
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body("JDBC URL validation failed");
        }
        log.info(jdbcUrl);
        DriverManager.getConnection(jdbcUrl);
        return ResponseEntity.ok("OK");
    }

    @RequestMapping("/db2")
    public ResponseEntity<String> db2(String jdbcUrlBase64) throws Exception{
        Class.forName("com.ibm.db2.jcc.DB2Driver");
        byte[] b = java.util.Base64.getDecoder().decode(jdbcUrlBase64);
        String jdbcUrl = new String(b);
        if (!isJdbcUrlSafe(jdbcUrl)) {
            log.error("JDBC SSRF check failed for db2 connection");
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body("JDBC URL validation failed");
        }
        log.info(jdbcUrl);
        DriverManager.getConnection(jdbcUrl);
        return ResponseEntity.ok("OK");
    }
}
