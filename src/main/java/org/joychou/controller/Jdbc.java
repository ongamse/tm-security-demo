package org.joychou.controller;

import lombok.extern.slf4j.Slf4j;
import org.joychou.security.SecurityUtil;
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

    private static final List<String> ALLOWED_JDBC_PREFIXES = Arrays.asList(
            "jdbc:postgresql://", "jdbc:db2://"
    );

    /**
     * Validate JDBC URL to prevent SSRF. Only allowed JDBC prefixes are accepted,
     * and the host portion must not resolve to a private/internal IP.
     */
    private static boolean validateJdbcUrl(String jdbcUrl, String requiredPrefix) {
        if (jdbcUrl == null || !jdbcUrl.startsWith(requiredPrefix)) {
            return false;
        }
        // Extract the host:port/db portion after the jdbc scheme prefix
        String remainder = jdbcUrl.substring(requiredPrefix.length());
        // Build an http URL from the remainder so we can validate the host
        String httpUrl = "http://" + remainder;
        try {
            URI uri = new URI(httpUrl);
            String host = uri.getHost();
            if (host == null || host.isEmpty()) {
                return false;
            }
            // Reuse the existing SSRF validation that checks for internal/private IPs
            return SecurityUtil.validateURLForSSRF("http://" + host);
        } catch (Exception e) {
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
        if (!validateJdbcUrl(jdbcUrl, "jdbc:postgresql://")) {
            return "JDBC URL validation failed: only jdbc:postgresql:// to non-internal hosts is allowed";
        }
        log.info(jdbcUrl);
        DriverManager.getConnection(jdbcUrl);
        return "OK";
    }

    @RequestMapping("/db2")
    public String db2(String jdbcUrlBase64) throws Exception{
        Class.forName("com.ibm.db2.jcc.DB2Driver");
        byte[] b = java.util.Base64.getDecoder().decode(jdbcUrlBase64);
        String jdbcUrl = new String(b);
        if (!validateJdbcUrl(jdbcUrl, "jdbc:db2://")) {
            return "JDBC URL validation failed: only jdbc:db2:// to non-internal hosts is allowed";
        }
        log.info(jdbcUrl);
        DriverManager.getConnection(jdbcUrl);
        return "OK";
    }
}
