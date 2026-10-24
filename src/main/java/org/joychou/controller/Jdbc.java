package org.joychou.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.net.InetAddress;
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
     * Allowlist of permitted JDBC host addresses. Only these hosts may be used
     * in user-supplied JDBC URLs to prevent SSRF via database connection strings.
     */
    private static final List<String> ALLOWED_JDBC_HOSTS = Arrays.asList(
            // Add allowed database hosts here, e.g. "db.example.com"
    );

    /**
     * Validate that a JDBC URL does not target internal/link-local/metadata addresses.
     * Also enforces an allowlist of permitted hosts when configured.
     *
     * @param jdbcUrl the JDBC connection URL
     * @throws IllegalArgumentException if the URL targets a disallowed host
     */
    private static void validateJdbcUrl(String jdbcUrl) {
        if (jdbcUrl == null || jdbcUrl.isEmpty()) {
            throw new IllegalArgumentException("JDBC URL must not be null or empty");
        }

        try {
            // JDBC URLs use the form jdbc:subprotocol://host:port/db — strip the "jdbc:" prefix
            // to parse the remainder as a standard URI
            String toParse = jdbcUrl;
            if (toParse.startsWith("jdbc:")) {
                toParse = toParse.substring(5);
            }
            // Some JDBC URLs may have a subprotocol prefix like "postgresql:" before "//host"
            int doubleSlash = toParse.indexOf("//");
            if (doubleSlash < 0) {
                throw new IllegalArgumentException("JDBC URL must contain a host component");
            }
            // Build a parseable URI: "http:" + everything from "//"
            URI uri = new URI("http:" + toParse.substring(doubleSlash));
            String host = uri.getHost();
            if (host == null || host.isEmpty()) {
                throw new IllegalArgumentException("JDBC URL must contain a valid host");
            }

            // Enforce host allowlist when configured
            if (!ALLOWED_JDBC_HOSTS.isEmpty() && !ALLOWED_JDBC_HOSTS.contains(host.toLowerCase())) {
                throw new IllegalArgumentException("JDBC host not in allowlist: " + host);
            }

            // Resolve and block internal/link-local/metadata IPs
            InetAddress resolved = InetAddress.getByName(host);
            if (resolved.isLoopbackAddress() || resolved.isLinkLocalAddress()
                    || resolved.isSiteLocalAddress() || resolved.isAnyLocalAddress()
                    || resolved.isMulticastAddress()) {
                throw new IllegalArgumentException("JDBC connections to internal/link-local addresses are not allowed");
            }
            // Block AWS/cloud metadata endpoint 169.254.x.x
            byte[] addr = resolved.getAddress();
            if (addr.length == 4 && (addr[0] & 0xFF) == 169 && (addr[1] & 0xFF) == 254) {
                throw new IllegalArgumentException("JDBC connections to metadata service addresses are not allowed");
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
