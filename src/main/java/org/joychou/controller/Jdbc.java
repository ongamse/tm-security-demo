package org.joychou.controller;

import lombok.extern.slf4j.Slf4j;
import org.joychou.security.ssrf.SSRFChecker;
import org.joychou.security.ssrf.SSRFException;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import java.nio.charset.StandardCharsets;
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

    private static final int MAX_JDBC_URL_LENGTH = 512;

    // Fixed driver schemes. The scheme of the connection url is always one of these literals, never request data.
    private static final String POSTGRESQL_SCHEME = "jdbc:postgresql://";
    private static final String DB2_SCHEME = "jdbc:db2://";

    // jdbc:<db>://host[:port]/database - no query string or driver properties are accepted.
    private static final Pattern POSTGRESQL_URL =
            Pattern.compile("^jdbc:postgresql://([A-Za-z0-9][A-Za-z0-9.-]{0,252})(?::([0-9]{1,5}))?/([A-Za-z0-9_.-]{0,63})$");
    private static final Pattern DB2_URL =
            Pattern.compile("^jdbc:db2://([A-Za-z0-9][A-Za-z0-9.-]{0,252})(?::([0-9]{1,5}))?/([A-Za-z0-9_.-]{0,63})$");

    /**
     * Only accept a plain jdbc url of the expected database type whose host is not an internal address.
     * Driver properties (socketFactory, loggerFile, ...) in the url are rejected. The returned url is rebuilt from
     * the validated components (fixed driver scheme, checked host, numeric port, database name).
     */
    private static String checkJdbcUrl(String jdbcUrlBase64, String driverScheme, Pattern allowed) {
        if (jdbcUrlBase64 == null || jdbcUrlBase64.length() > MAX_JDBC_URL_LENGTH * 2) {
            throw new IllegalArgumentException("Illegal jdbc url");
        }
        String decoded = new String(java.util.Base64.getDecoder().decode(jdbcUrlBase64), StandardCharsets.UTF_8);
        if (decoded.length() > MAX_JDBC_URL_LENGTH) {
            throw new IllegalArgumentException("Illegal jdbc url");
        }
        Matcher m = allowed.matcher(decoded);
        if (!m.matches()) {
            throw new IllegalArgumentException("Illegal jdbc url");
        }
        String host = m.group(1);
        SSRFChecker.checkHost(host);

        StringBuilder rebuilt = new StringBuilder(driverScheme).append(host);
        if (m.group(2) != null) {
            int port = Integer.parseInt(m.group(2));
            if (port < 1 || port > 65535) {
                throw new IllegalArgumentException("Illegal jdbc url");
            }
            rebuilt.append(':').append(port);
        }
        rebuilt.append('/').append(m.group(3));
        return rebuilt.toString();
    }

    @ExceptionHandler({IllegalArgumentException.class, SSRFException.class})
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public String illegalJdbcUrl() {
        return "Illegal jdbc url";
    }

    /**
     * <a href="https://github.com/JoyChou93/java-sec-code/wiki/CVE-2022-21724">CVE-2022-21724</a>
     */
    @RequestMapping("/postgresql")
    public void postgresql(String jdbcUrlBase64) throws Exception{
        String jdbcUrl = checkJdbcUrl(jdbcUrlBase64, POSTGRESQL_SCHEME, POSTGRESQL_URL);
        log.info("postgresql jdbc connect");
        DriverManager.getConnection(jdbcUrl);
    }

    @RequestMapping("/db2")
    public void db2(String jdbcUrlBase64) throws Exception{
        Class.forName("com.ibm.db2.jcc.DB2Driver");
        String jdbcUrl = checkJdbcUrl(jdbcUrlBase64, DB2_SCHEME, DB2_URL);
        log.info("db2 jdbc connect");
        DriverManager.getConnection(jdbcUrl);
    }
}
