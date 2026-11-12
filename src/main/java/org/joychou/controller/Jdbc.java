package org.joychou.controller;

import lombok.extern.slf4j.Slf4j;
import org.joychou.security.SecurityUtil;
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
        String jdbcUrl = checkJdbcUrl(new String(b, java.nio.charset.StandardCharsets.UTF_8), "jdbc:postgresql://");
        log.info("jdbc postgresql connect");
        DriverManager.getConnection(jdbcUrl);
    }

    @RequestMapping("/db2")
    public void db2(String jdbcUrlBase64) throws Exception{
        Class.forName("com.ibm.db2.jcc.DB2Driver");
        byte[] b = java.util.Base64.getDecoder().decode(jdbcUrlBase64);
        String jdbcUrl = checkJdbcUrl(new String(b, java.nio.charset.StandardCharsets.UTF_8), "jdbc:db2://");
        log.info("jdbc db2 connect");
        DriverManager.getConnection(jdbcUrl);
    }

    /**
     * Allowlist a user supplied JDBC url: it must use the expected driver prefix, point to a
     * public host (no loopback / link-local / private / metadata addresses) and must not carry
     * any driver properties (query string or ';' properties such as socketFactory / sslfactory,
     * which make the driver instantiate arbitrary classes).
     *
     * @param jdbcUrl url decoded from the request
     * @param prefix  allowed driver prefix, e.g. jdbc:postgresql://
     * @return the validated url
     * @throws IllegalArgumentException if the url is not allowed
     */
    private static String checkJdbcUrl(String jdbcUrl, String prefix) {
        if (jdbcUrl == null || !jdbcUrl.startsWith(prefix)) {
            throw new IllegalArgumentException("Illegal jdbc url");
        }
        if (jdbcUrl.indexOf('?') >= 0 || jdbcUrl.indexOf(';') >= 0 || jdbcUrl.indexOf('&') >= 0
                || jdbcUrl.indexOf('\\') >= 0 || jdbcUrl.indexOf('@') >= 0 || jdbcUrl.indexOf('%') >= 0) {
            throw new IllegalArgumentException("Illegal jdbc url");
        }
        try {
            // strip the "jdbc:" prefix so that java.net.URI can parse host and port
            URI uri = new URI(jdbcUrl.substring("jdbc:".length()));
            if (!SecurityUtil.isPublicHost(uri.getHost())) {
                throw new IllegalArgumentException("Illegal jdbc url");
            }
        } catch (java.net.URISyntaxException e) {
            throw new IllegalArgumentException("Illegal jdbc url");
        }
        return jdbcUrl;
    }
}
