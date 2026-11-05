package org.joychou.controller;

import lombok.extern.slf4j.Slf4j;
import org.joychou.security.ssrf.SSRFChecker;
import org.springframework.web.bind.annotation.RequestMapping;
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

    // jdbc:<db>://host[:port]/database - no query string or driver properties are accepted.
    private static final Pattern POSTGRESQL_URL =
            Pattern.compile("^jdbc:postgresql://([A-Za-z0-9][A-Za-z0-9.-]*)(?::[0-9]{1,5})?/[A-Za-z0-9_.-]*$");
    private static final Pattern DB2_URL =
            Pattern.compile("^jdbc:db2://([A-Za-z0-9][A-Za-z0-9.-]*)(?::[0-9]{1,5})?/[A-Za-z0-9_.-]*$");

    /**
     * Only accept a plain jdbc url of the expected database type whose host is not an internal address.
     * Driver properties (socketFactory, loggerFile, ...) in the url are rejected.
     */
    private static String checkJdbcUrl(String jdbcUrlBase64, Pattern allowed) {
        if (jdbcUrlBase64 == null) {
            throw new IllegalArgumentException("Illegal jdbc url");
        }
        String jdbcUrl = new String(java.util.Base64.getDecoder().decode(jdbcUrlBase64), StandardCharsets.UTF_8);
        Matcher m = allowed.matcher(jdbcUrl);
        if (!m.matches()) {
            throw new IllegalArgumentException("Illegal jdbc url");
        }
        SSRFChecker.checkHost(m.group(1));
        return jdbcUrl;
    }

    /**
     * <a href="https://github.com/JoyChou93/java-sec-code/wiki/CVE-2022-21724">CVE-2022-21724</a>
     */
    @RequestMapping("/postgresql")
    public void postgresql(String jdbcUrlBase64) throws Exception{
        String jdbcUrl = checkJdbcUrl(jdbcUrlBase64, POSTGRESQL_URL);
        log.info("postgresql jdbc connect");
        DriverManager.getConnection(jdbcUrl);
    }

    @RequestMapping("/db2")
    public void db2(String jdbcUrlBase64) throws Exception{
        Class.forName("com.ibm.db2.jcc.DB2Driver");
        String jdbcUrl = checkJdbcUrl(jdbcUrlBase64, DB2_URL);
        log.info("db2 jdbc connect");
        DriverManager.getConnection(jdbcUrl);
    }
}
