package org.joychou.controller;

import lombok.extern.slf4j.Slf4j;
import org.joychou.security.ssrf.SSRFChecker;
import org.joychou.security.ssrf.SSRFException;
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

    // Only plain jdbc:<driver>://host[:port]/database urls. No query string or driver properties,
    // which are what the JDBC driver attacks rely on.
    private static final Pattern POSTGRESQL_URL =
            Pattern.compile("^jdbc:postgresql://([A-Za-z0-9.-]{1,253})(?::([0-9]{1,5}))?/([A-Za-z0-9_]{1,63})$");
    private static final Pattern DB2_URL =
            Pattern.compile("^jdbc:db2://([A-Za-z0-9.-]{1,253})(?::([0-9]{1,5}))?/([A-Za-z0-9_]{1,63})$");

    private static final int POSTGRESQL_DEFAULT_PORT = 5432;
    private static final int DB2_DEFAULT_PORT = 50000;
    // pgjdbc 42.3.1: ssl=true plus sslmode=verify-full (certificate chain and host name verified)
    private static final String POSTGRESQL_TLS_OPTIONS = "?ssl=true&sslmode=verify-full";
    // IBM JCC: TLS connection, appended after the database name
    private static final String DB2_TLS_OPTIONS = ":sslConnection=true;";

    /**
     * Allow only the expected url shape and a host that does not resolve to an internal address.
     *
     * @throws IllegalArgumentException if the url is not allowed
     */
    private static String checkJdbcUrl(String jdbcUrl, Pattern pattern) {
        Matcher m = pattern.matcher(jdbcUrl);
        if (!m.matches()) {
            throw new IllegalArgumentException("Illegal jdbc url");
        }
        String driver = jdbcUrl.startsWith("jdbc:db2:") ? "db2" : "postgresql";
        int port = "db2".equals(driver) ? DB2_DEFAULT_PORT : POSTGRESQL_DEFAULT_PORT;
        if (m.group(2) != null) {
            port = Integer.parseInt(m.group(2));
            if (port < 1 || port > 65535) {
                throw new IllegalArgumentException("Illegal jdbc url");
            }
        }
        String portPart = ":" + port;
        String db = m.group(3);
        try {
            // host must be an entry (or sub-domain) of the configured safe-domain list and must not
            // resolve to an internal address; the connection url is rebuilt from the validated parts
            String host = SSRFChecker.safeHost(m.group(1));
            // TLS is always required; the options are constants, never taken from user input
            String tlsOptions = "db2".equals(driver) ? DB2_TLS_OPTIONS : POSTGRESQL_TLS_OPTIONS;
            return "jdbc:" + driver + "://" + host + portPart + "/" + db + tlsOptions;
        } catch (SSRFException e) {
            throw new IllegalArgumentException("Illegal jdbc url");
        }
    }

    /**
     * <a href="https://github.com/JoyChou93/java-sec-code/wiki/CVE-2022-21724">CVE-2022-21724</a>
     */
    @RequestMapping("/postgresql")
    public void postgresql(String jdbcUrlBase64) throws Exception{
        byte[] b = java.util.Base64.getDecoder().decode(jdbcUrlBase64);
        String jdbcUrl = checkJdbcUrl(new String(b), POSTGRESQL_URL);
        log.info("postgresql jdbc connection requested");
        DriverManager.getConnection(jdbcUrl);
    }

    @RequestMapping("/db2")
    public void db2(String jdbcUrlBase64) throws Exception{
        Class.forName("com.ibm.db2.jcc.DB2Driver");
        byte[] b = java.util.Base64.getDecoder().decode(jdbcUrlBase64);
        String jdbcUrl = checkJdbcUrl(new String(b), DB2_URL);
        log.info("db2 jdbc connection requested");
        DriverManager.getConnection(jdbcUrl);
    }
}
