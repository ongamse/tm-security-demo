package org.joychou.controller;

import lombok.extern.slf4j.Slf4j;
import org.joychou.security.ssrf.SSRFChecker;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

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
        // Extract host from JDBC URL and validate against SSRF
        String httpUrl = jdbcUrlToHttpUrl(jdbcUrl);
        if (httpUrl != null && !SSRFChecker.isSSRFSafe(httpUrl)) {
            throw new IllegalArgumentException("SSRF blocked: JDBC URL targets a private/reserved IP");
        }
        log.info(jdbcUrl);
        DriverManager.getConnection(jdbcUrl);
    }

    @RequestMapping("/db2")
    public void db2(String jdbcUrlBase64) throws Exception{
        Class.forName("com.ibm.db2.jcc.DB2Driver");
        byte[] b = java.util.Base64.getDecoder().decode(jdbcUrlBase64);
        String jdbcUrl = new String(b);
        // Extract host from JDBC URL and validate against SSRF
        String httpUrl = jdbcUrlToHttpUrl(jdbcUrl);
        if (httpUrl != null && !SSRFChecker.isSSRFSafe(httpUrl)) {
            throw new IllegalArgumentException("SSRF blocked: JDBC URL targets a private/reserved IP");
        }
        log.info(jdbcUrl);
        DriverManager.getConnection(jdbcUrl);
    }

    /**
     * Extracts host from a JDBC URL and converts it to an HTTP URL for SSRF validation.
     * JDBC URLs typically follow the pattern jdbc:subprotocol://host:port/...
     */
    private String jdbcUrlToHttpUrl(String jdbcUrl) {
        try {
            // Strip the "jdbc:" prefix to get a parseable URI
            if (jdbcUrl != null && jdbcUrl.startsWith("jdbc:")) {
                String subUri = jdbcUrl.substring(5); // remove "jdbc:"
                // Handle double-prefix like jdbc:postgresql:// or jdbc:db2://
                int schemeEnd = subUri.indexOf("://");
                if (schemeEnd >= 0) {
                    String hostPart = subUri.substring(schemeEnd + 3);
                    // Extract host:port before any / or ? or ;
                    int slashIdx = hostPart.indexOf('/');
                    int qIdx = hostPart.indexOf('?');
                    int semiIdx = hostPart.indexOf(';');
                    int end = hostPart.length();
                    if (slashIdx >= 0) end = Math.min(end, slashIdx);
                    if (qIdx >= 0) end = Math.min(end, qIdx);
                    if (semiIdx >= 0) end = Math.min(end, semiIdx);
                    String hostPort = hostPart.substring(0, end);
                    return "http://" + hostPort;
                }
            }
        } catch (Exception e) {
            log.error("Failed to parse JDBC URL for SSRF check: " + e.getMessage());
        }
        return null;
    }
}
