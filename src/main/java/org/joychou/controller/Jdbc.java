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

    private static final List<String> ALLOWED_JDBC_PREFIXES = Arrays.asList(
            "jdbc:postgresql://", "jdbc:db2://"
    );

    /**
     * Validate JDBC URL: only allowed prefixes and the host must not resolve to an internal IP.
     */
    private static void validateJdbcUrl(String jdbcUrl, String requiredPrefix) throws Exception {
        if (jdbcUrl == null || !jdbcUrl.startsWith(requiredPrefix)) {
            throw new IllegalArgumentException("Invalid JDBC URL: must start with " + requiredPrefix);
        }
        // Extract the host portion by parsing the part after "jdbc:"
        String urlPart = jdbcUrl.substring("jdbc:".length());
        // Replace the db-specific scheme with http so URI can parse host
        String httpUrl;
        if (urlPart.startsWith("postgresql://")) {
            httpUrl = "http://" + urlPart.substring("postgresql://".length());
        } else if (urlPart.startsWith("db2://")) {
            httpUrl = "http://" + urlPart.substring("db2://".length());
        } else {
            throw new IllegalArgumentException("Unsupported JDBC scheme");
        }
        URI uri = new URI(httpUrl);
        String host = uri.getHost();
        if (host == null || host.isEmpty()) {
            throw new IllegalArgumentException("Invalid JDBC URL: could not extract host");
        }
        String ip = SSRFChecker.host2ip(host);
        if (ip.isEmpty() || SSRFChecker.isInternalIp(ip)) {
            throw new IllegalArgumentException("JDBC URL host resolves to an internal or invalid IP");
        }
    }

    /**
     * <a href="https://github.com/JoyChou93/java-sec-code/wiki/CVE-2022-21724">CVE-2022-21724</a>
     */
    @RequestMapping("/postgresql")
    public void postgresql(String jdbcUrlBase64) throws Exception{
        byte[] b = java.util.Base64.getDecoder().decode(jdbcUrlBase64);
        String jdbcUrl = new String(b);
        validateJdbcUrl(jdbcUrl, "jdbc:postgresql://");
        log.info(jdbcUrl);
        DriverManager.getConnection(jdbcUrl);
    }

    @RequestMapping("/db2")
    public void db2(String jdbcUrlBase64) throws Exception{
        Class.forName("com.ibm.db2.jcc.DB2Driver");
        byte[] b = java.util.Base64.getDecoder().decode(jdbcUrlBase64);
        String jdbcUrl = new String(b);
        validateJdbcUrl(jdbcUrl, "jdbc:db2://");
        log.info(jdbcUrl);
        DriverManager.getConnection(jdbcUrl);
    }
}
