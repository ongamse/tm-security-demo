package org.joychou.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
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

    private static final List<String> ALLOWED_JDBC_PREFIXES = Arrays.asList(
            "jdbc:postgresql://", "jdbc:db2://"
    );

    /**
     * Validate JDBC URL: only allow known prefixes and non-internal hosts.
     */
    private static boolean isJdbcUrlSafe(String jdbcUrl) {
        if (jdbcUrl == null) {
            return false;
        }

        boolean prefixAllowed = false;
        for (String prefix : ALLOWED_JDBC_PREFIXES) {
            if (jdbcUrl.startsWith(prefix)) {
                prefixAllowed = true;
                break;
            }
        }
        if (!prefixAllowed) {
            log.error("[-] JDBC URL rejected: unrecognized prefix: " + jdbcUrl);
            return false;
        }

        // Extract host from JDBC URL by parsing the part after "jdbc:"
        try {
            String uriPart = jdbcUrl.substring("jdbc:".length());
            // Handle jdbc:postgresql://host:port/db or jdbc:db2://host:port/db
            URI uri = new URI(uriPart);
            String host = uri.getHost();
            if (host == null || host.isEmpty()) {
                log.error("[-] JDBC URL rejected: no host found");
                return false;
            }
            InetAddress addr = InetAddress.getByName(host);
            if (addr.isLoopbackAddress() || addr.isLinkLocalAddress()
                    || addr.isSiteLocalAddress() || addr.isAnyLocalAddress()) {
                log.error("[-] JDBC URL rejected: internal IP for host: " + host);
                return false;
            }
        } catch (Exception e) {
            log.error("[-] JDBC URL rejected: parse error: " + e.getMessage());
            return false;
        }

        return true;
    }

    /**
     * <a href="https://github.com/JoyChou93/java-sec-code/wiki/CVE-2022-21724">CVE-2022-21724</a>
     */
    @RequestMapping("/postgresql")
    public ResponseEntity<String> postgresql(String jdbcUrlBase64) throws Exception{
        byte[] b = java.util.Base64.getDecoder().decode(jdbcUrlBase64);
        String jdbcUrl = new String(b);
        if (!isJdbcUrlSafe(jdbcUrl)) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body("[-] JDBC URL validation failed");
        }
        log.info(jdbcUrl);
        DriverManager.getConnection(jdbcUrl);
        return ResponseEntity.ok("OK");
    }

    @RequestMapping("/db2")
    public ResponseEntity<String> db2(String jdbcUrlBase64) throws Exception{
        byte[] b = java.util.Base64.getDecoder().decode(jdbcUrlBase64);
        String jdbcUrl = new String(b);
        if (!isJdbcUrlSafe(jdbcUrl)) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body("[-] JDBC URL validation failed");
        }
        Class.forName("com.ibm.db2.jcc.DB2Driver");
        log.info(jdbcUrl);
        DriverManager.getConnection(jdbcUrl);
        return ResponseEntity.ok("OK");
    }
}
