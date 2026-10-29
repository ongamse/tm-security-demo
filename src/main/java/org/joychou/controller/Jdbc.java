package org.joychou.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.sql.DriverManager;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Jdbc Attack @2023.04
 */
@Slf4j
@RestController
@RequestMapping("/jdbc")
public class Jdbc {

    // Allowlist of hosts a JDBC url may point to.
    private static final java.util.List<String> ALLOWED_JDBC_HOSTS = java.util.Arrays.asList("localhost", "127.0.0.1");

    // Strict form: jdbc:<postgresql|db2>://host[:port]/database. No query string or
    // driver properties (e.g. socketFactory, loggerFile) are allowed.
    private static final Pattern JDBC_URL_PATTERN = Pattern.compile(
            "^jdbc:(postgresql|db2)://([A-Za-z0-9.-]+)(?::(\\d{1,5}))?/([A-Za-z0-9_-]+)$");

    /**
     * Validate the scheme, host and format of a user supplied JDBC url.
     * Fails closed with IllegalArgumentException.
     */
    private static String validateJdbcUrl(String jdbcUrl, String expectedSubprotocol) {
        Matcher m = JDBC_URL_PATTERN.matcher(jdbcUrl);
        if (!m.matches() || !expectedSubprotocol.equals(m.group(1))) {
            throw new IllegalArgumentException("Illegal jdbc url");
        }
        // Pick the host from the constant allowlist instead of using the request value.
        String requestedHost = m.group(2).toLowerCase(java.util.Locale.ROOT);
        String host = null;
        for (String allowed : ALLOWED_JDBC_HOSTS) {
            if (allowed.equals(requestedHost)) {
                host = allowed;
                break;
            }
        }
        if (host == null) {
            throw new IllegalArgumentException("Illegal jdbc url");
        }
        // The prefix is a constant chosen by the endpoint, never taken from the request.
        final String prefix = "postgresql".equals(expectedSubprotocol) ? "jdbc:postgresql://" : "jdbc:db2://";
        StringBuilder rebuilt = new StringBuilder(prefix).append(host);
        if (m.group(3) != null) {
            int port = Integer.parseInt(m.group(3));
            if (port < 1 || port > 65535) {
                throw new IllegalArgumentException("Illegal jdbc url");
            }
            rebuilt.append(':').append(port);
        }
        rebuilt.append('/').append(m.group(4));
        return rebuilt.toString();
    }

    /**
     * <a href="https://github.com/JoyChou93/java-sec-code/wiki/CVE-2022-21724">CVE-2022-21724</a>
     */
    @RequestMapping("/postgresql")
    public void postgresql(String jdbcUrlBase64) throws Exception{
        byte[] b = java.util.Base64.getDecoder().decode(jdbcUrlBase64);
        String jdbcUrl = new String(b);
        DriverManager.getConnection(validateJdbcUrl(jdbcUrl, "postgresql"));
    }

    @RequestMapping("/db2")
    public void db2(String jdbcUrlBase64) throws Exception{
        Class.forName("com.ibm.db2.jcc.DB2Driver");
        byte[] b = java.util.Base64.getDecoder().decode(jdbcUrlBase64);
        String jdbcUrl = new String(b);
        DriverManager.getConnection(validateJdbcUrl(jdbcUrl, "db2"));
    }
}
