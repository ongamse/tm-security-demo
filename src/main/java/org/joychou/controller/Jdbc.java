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

    // Allowed JDBC URL prefixes (scheme + subprotocol)
    private static final List<String> ALLOWED_JDBC_PREFIXES = Arrays.asList(
            "jdbc:postgresql://", "jdbc:db2://"
    );

    /**
     * Validate JDBC URL: must use an allowed prefix and must not target internal IPs.
     */
    private static boolean isJdbcUrlSafe(String jdbcUrl, String requiredPrefix) {
        if (jdbcUrl == null || !jdbcUrl.startsWith(requiredPrefix)) {
            return false;
        }
        // Extract the host portion by parsing the part after the JDBC prefix as a URI
        String uriPart = jdbcUrl.substring(requiredPrefix.length() - "//".length());
        try {
            URI uri = new URI("jdbc" + uriPart);
            String host = uri.getHost();
            if (host == null || host.isEmpty()) {
                return false;
            }
            // Reject internal/private IPs
            if (SSRFChecker.isInternalIpByUrl("http://" + host)) {
                return false;
            }
        } catch (Exception e) {
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
        if (!isJdbcUrlSafe(jdbcUrl, "jdbc:postgresql://")) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("[-] JDBC URL validation failed");
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
        if (!isJdbcUrlSafe(jdbcUrl, "jdbc:db2://")) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("[-] JDBC URL validation failed");
        }
        log.info(jdbcUrl);
        DriverManager.getConnection(jdbcUrl);
        return ResponseEntity.ok("OK");
    }
}
