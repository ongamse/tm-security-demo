package org.joychou.controller;

import lombok.extern.slf4j.Slf4j;
import org.joychou.security.ssrf.SSRFChecker;
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
            Pattern.compile("^jdbc:postgresql://([A-Za-z0-9.-]{1,253})(?::[0-9]{1,5})?/[A-Za-z0-9_]{1,63}$");
    private static final Pattern DB2_URL =
            Pattern.compile("^jdbc:db2://([A-Za-z0-9.-]{1,253})(?::[0-9]{1,5})?/[A-Za-z0-9_]{1,63}$");

    /**
     * Allow only the expected url shape and a host that does not resolve to an internal address.
     *
     * @throws IllegalArgumentException if the url is not allowed
     */
    private static String checkJdbcUrl(String jdbcUrl, Pattern pattern) {
        Matcher m = pattern.matcher(jdbcUrl);
        if (!m.matches() || SSRFChecker.isInternalIpByUrl("http://" + m.group(1) + "/")) {
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
