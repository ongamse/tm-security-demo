package org.joychou.controller;

import lombok.extern.slf4j.Slf4j;
import org.joychou.security.SecurityUtil;
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

    /**
     * Strict JDBC URL shape: fixed subprotocol, plain host[:port][/database]. Connection
     * properties (query string, ';' or ':' property lists such as socketFactory,
     * loggerFile, clientRerouteServerListJNDIName ...) are rejected.
     */
    private static final Pattern POSTGRESQL_URL =
            Pattern.compile("^jdbc:postgresql://([A-Za-z0-9.-]{1,253})(?::(\\d{1,5}))?(?:/([A-Za-z0-9_.-]{1,63}))?$");
    private static final Pattern DB2_URL =
            Pattern.compile("^jdbc:db2://([A-Za-z0-9.-]{1,253})(?::(\\d{1,5}))?(?:/([A-Za-z0-9_.-]{1,63}))?$");

    /**
     * Decode and validate the user supplied JDBC URL: allowlisted subprotocol, no connection
     * properties, and a host that only resolves to public addresses.
     */
    private static String checkedJdbcUrl(String jdbcUrlBase64, Pattern allowed) {
        if (jdbcUrlBase64 == null) {
            throw new IllegalArgumentException("Illegal jdbc url");
        }
        String jdbcUrl = new String(java.util.Base64.getDecoder().decode(jdbcUrlBase64), StandardCharsets.UTF_8);
        Matcher m = allowed.matcher(jdbcUrl);
        if (!m.matches() || !SecurityUtil.isSafeOutboundHost(m.group(1))) {
            throw new IllegalArgumentException("Illegal jdbc url");
        }
        return jdbcUrl;
    }

    /**
     * <a href="https://github.com/JoyChou93/java-sec-code/wiki/CVE-2022-21724">CVE-2022-21724</a>
     */
    @RequestMapping("/postgresql")
    public void postgresql(String jdbcUrlBase64) throws Exception{
        String jdbcUrl = checkedJdbcUrl(jdbcUrlBase64, POSTGRESQL_URL);
        log.info(jdbcUrl);
        DriverManager.getConnection(jdbcUrl);
    }

    @RequestMapping("/db2")
    public void db2(String jdbcUrlBase64) throws Exception{
        Class.forName("com.ibm.db2.jcc.DB2Driver");
        String jdbcUrl = checkedJdbcUrl(jdbcUrlBase64, DB2_URL);
        log.info(jdbcUrl);
        DriverManager.getConnection(jdbcUrl);
    }
}
