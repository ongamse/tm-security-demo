package org.joychou.controller;

import lombok.extern.slf4j.Slf4j;
import org.joychou.security.SecurityUtil;
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
        log.info("JDBC postgresql connection requested");
        validateJdbcUrl(jdbcUrl);
        DriverManager.getConnection(jdbcUrl);
    }

    @RequestMapping("/db2")
    public void db2(String jdbcUrlBase64) throws Exception{
        Class.forName("com.ibm.db2.jcc.DB2Driver");
        byte[] b = java.util.Base64.getDecoder().decode(jdbcUrlBase64);
        String jdbcUrl = new String(b);
        log.info("JDBC db2 connection requested");
        validateJdbcUrl(jdbcUrl);
        DriverManager.getConnection(jdbcUrl);
    }

    /**
     * Validate a JDBC URL to ensure its host does not resolve to an internal/private IP.
     * Extracts the host portion from the JDBC sub-URI and checks it against the SSRF block list.
     */
    private void validateJdbcUrl(String jdbcUrl) {
        if (jdbcUrl == null || !jdbcUrl.startsWith("jdbc:")) {
            throw new IllegalArgumentException("Invalid JDBC URL");
        }

        // Extract the sub-URI after "jdbc:" (e.g., "postgresql://host:5432/db")
        String subUri = jdbcUrl.substring(5);
        try {
            URI uri = new URI(subUri);
            String host = uri.getHost();
            if (host == null || host.isEmpty()) {
                // Try parsing after the next colon for formats like jdbc:db2://host:port/db
                int schemeEnd = subUri.indexOf("://");
                if (schemeEnd >= 0) {
                    uri = new URI("http" + subUri.substring(schemeEnd));
                    host = uri.getHost();
                }
            }
            if (host == null || host.isEmpty()) {
                throw new IllegalArgumentException("Cannot extract host from JDBC URL");
            }
            String ip = SSRFChecker.host2ip(host);
            if (ip == null || ip.isEmpty()) {
                throw new IllegalArgumentException("Cannot resolve JDBC host: " + host);
            }
            if (SSRFChecker.isInternalIp(ip)) {
                throw new IllegalArgumentException("JDBC URL targets an internal/private address");
            }
        } catch (IllegalArgumentException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalArgumentException("Invalid JDBC URL format");
        }
    }
}
