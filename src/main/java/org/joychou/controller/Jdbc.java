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

    // Allowlist of permitted JDBC hosts to prevent SSRF via JDBC connections
    private static final List<String> JDBC_ALLOWED_HOSTS = Arrays.asList("localhost", "127.0.0.1");

    /**
     * Validate that a JDBC URL only connects to allowed hosts.
     * Extracts the host from the JDBC sub-URI and checks against the allowlist.
     *
     * @param jdbcUrl the JDBC URL to validate
     * @throws SecurityException if the host is not in the allowlist
     */
    private static void validateJdbcUrl(String jdbcUrl) {
        if (jdbcUrl == null || jdbcUrl.isEmpty()) {
            throw new SecurityException("JDBC URL is null or empty");
        }
        try {
            // JDBC URLs have the form jdbc:<subprotocol>://<host>:<port>/<database>
            // Strip the leading "jdbc:" to get a parseable URI
            String subUri = jdbcUrl;
            if (subUri.startsWith("jdbc:")) {
                subUri = subUri.substring(5);
            }
            // Some JDBC URLs have another subprotocol prefix like "postgresql:" before "//"
            int schemeEnd = subUri.indexOf("://");
            if (schemeEnd > 0) {
                subUri = "http" + subUri.substring(schemeEnd);
            } else {
                throw new SecurityException("Invalid JDBC URL format");
            }
            URI uri = new URI(subUri);
            String host = uri.getHost();
            if (host == null || host.isEmpty()) {
                throw new SecurityException("Could not extract host from JDBC URL");
            }
            host = host.toLowerCase();
            if (!JDBC_ALLOWED_HOSTS.contains(host)) {
                throw new SecurityException("JDBC host not in allowlist: " + host);
            }
        } catch (SecurityException e) {
            throw e;
        } catch (Exception e) {
            throw new SecurityException("Invalid JDBC URL: " + e.getMessage());
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
        log.info(SecurityUtil.sanitizeForLog(jdbcUrl));
        DriverManager.getConnection(jdbcUrl);
    }

    @RequestMapping("/db2")
    public void db2(String jdbcUrlBase64) throws Exception{
        Class.forName("com.ibm.db2.jcc.DB2Driver");
        byte[] b = java.util.Base64.getDecoder().decode(jdbcUrlBase64);
        String jdbcUrl = new String(b);
        validateJdbcUrl(jdbcUrl);
        log.info(SecurityUtil.sanitizeForLog(jdbcUrl));
        DriverManager.getConnection(jdbcUrl);
    }
}
