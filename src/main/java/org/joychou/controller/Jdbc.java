package org.joychou.controller;

import lombok.extern.slf4j.Slf4j;
import org.joychou.security.ssrf.SSRFChecker;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.sql.DriverManager;

/**
 * Jdbc Attack @2023.04
 */
@Slf4j
@RestController
@RequestMapping("/jdbc")
public class Jdbc {

    private static final String POSTGRESQL_PREFIX = "jdbc:postgresql://";
    private static final String DB2_PREFIX = "jdbc:db2://";

    /**
     * Allow only <code>jdbc:postgresql://host[:port]/db</code> or <code>jdbc:db2://host[:port]/db</code>,
     * without driver properties (query string / semicolon properties such as socketFactory), and
     * with a host that resolves only to public addresses.
     *
     * @param jdbcUrl decoded user supplied jdbc url
     * @param prefix  the single allowed jdbc url prefix
     * @return the validated jdbc url
     */
    private static String validateJdbcUrl(String jdbcUrl, String prefix) {
        if (jdbcUrl == null || !jdbcUrl.startsWith(prefix)) {
            throw new IllegalArgumentException("Illegal jdbc url");
        }
        if (jdbcUrl.indexOf('?') >= 0 || jdbcUrl.indexOf(';') >= 0 || jdbcUrl.indexOf('&') >= 0
                || jdbcUrl.indexOf('@') >= 0 || jdbcUrl.indexOf(',') >= 0) {
            throw new IllegalArgumentException("Illegal jdbc url");
        }
        String host;
        try {
            // Reuse the URI parser on the part after "jdbc:" to extract scheme/host/port.
            host = new URI(jdbcUrl.substring("jdbc:".length())).getHost();
            SSRFChecker.resolvePublicAddresses(host);
        } catch (Exception e) {
            throw new IllegalArgumentException("Illegal jdbc url");
        }
        return jdbcUrl;
    }

    /**
     * <a href="https://github.com/JoyChou93/java-sec-code/wiki/CVE-2022-21724">CVE-2022-21724</a>
     */
    @RequestMapping("/postgresql")
    public void postgresql(String jdbcUrlBase64) throws Exception{
        byte[] b = java.util.Base64.getDecoder().decode(jdbcUrlBase64);
        String jdbcUrl = validateJdbcUrl(new String(b, StandardCharsets.UTF_8), POSTGRESQL_PREFIX);
        log.info("Connecting to validated postgresql url");
        DriverManager.getConnection(jdbcUrl);
    }

    @RequestMapping("/db2")
    public void db2(String jdbcUrlBase64) throws Exception{
        Class.forName("com.ibm.db2.jcc.DB2Driver");
        byte[] b = java.util.Base64.getDecoder().decode(jdbcUrlBase64);
        String jdbcUrl = validateJdbcUrl(new String(b, StandardCharsets.UTF_8), DB2_PREFIX);
        log.info("Connecting to validated db2 url");
        DriverManager.getConnection(jdbcUrl);
    }
}
