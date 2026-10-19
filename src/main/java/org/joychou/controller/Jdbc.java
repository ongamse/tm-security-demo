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

    // Allowlist of permitted JDBC host suffixes
    private static final List<String> ALLOWED_JDBC_HOSTS = Arrays.asList(
            "localhost"
    );

    /**
     * Validate that a JDBC URL does not target an internal/private network address.
     * Only connections to explicitly allowed hosts are permitted.
     */
    private static void validateJdbcUrl(String jdbcUrl) {
        if (jdbcUrl == null) {
            throw new IllegalArgumentException("JDBC URL must not be null");
        }
        try {
            // JDBC URLs like jdbc:postgresql://host:port/db — strip "jdbc:" prefix to parse as URI
            String uriPart = jdbcUrl;
            if (uriPart.startsWith("jdbc:")) {
                uriPart = uriPart.substring(5);
            }
            URI uri = new URI(uriPart);
            String host = uri.getHost();
            if (host == null || host.isEmpty()) {
                throw new IllegalArgumentException("JDBC URL has no valid host");
            }
            // Block internal/private IP ranges
            if (SSRFChecker.isInternalIpByUrl("http://" + host)) {
                throw new IllegalArgumentException("JDBC connections to internal network addresses are not allowed");
            }
            // Check against allowlist
            boolean allowed = false;
            for (String allowedHost : ALLOWED_JDBC_HOSTS) {
                if (host.equalsIgnoreCase(allowedHost) || host.endsWith("." + allowedHost)) {
                    allowed = true;
                    break;
                }
            }
            if (!allowed) {
                throw new IllegalArgumentException("JDBC host is not in the allowed hosts list: " + host);
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
