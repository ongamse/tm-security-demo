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

    /**
     * <a href="https://github.com/JoyChou93/java-sec-code/wiki/CVE-2022-21724">CVE-2022-21724</a>
     */
    // jdbc:<vendor>://host[:port]/database - no driver properties (socketFactory, etc.) in the url.
    private static final Pattern POSTGRESQL_URL =
            Pattern.compile("^jdbc:postgresql://([A-Za-z0-9.-]+)(?::([0-9]{1,5}))?/([A-Za-z0-9_]+)$");
    private static final Pattern DB2_URL =
            Pattern.compile("^jdbc:db2://([A-Za-z0-9.-]+)(?::([0-9]{1,5}))?/([A-Za-z0-9_]+)$");

    /**
     * Only a plain jdbc url whose host resolves to a public address is accepted, so the server
     * cannot be made to connect to internal hosts or load driver classes via url properties.
     */
    private static String requireSafeJdbcUrl(String jdbcUrlBase64, String vendor, Pattern allowed) {
        String jdbcUrl = new String(java.util.Base64.getDecoder().decode(jdbcUrlBase64),
                java.nio.charset.StandardCharsets.UTF_8);
        Matcher m = allowed.matcher(jdbcUrl);
        if (!m.matches() || !SSRFChecker.isSafeOutboundHost(m.group(1))) {
            throw new IllegalArgumentException("Illegal jdbc url");
        }
        int port = -1;
        if (m.group(2) != null) {
            port = Integer.parseInt(m.group(2));
            if (port > 65535) {
                throw new IllegalArgumentException("Illegal jdbc url");
            }
        }
        // Re-construct the url from the validated host, port and database name.
        return "jdbc:" + vendor + "://" + m.group(1) + (port >= 0 ? ":" + port : "") + "/" + m.group(3);
    }

    @RequestMapping("/postgresql")
    public void postgresql(String jdbcUrlBase64) throws Exception{
        String jdbcUrl = requireSafeJdbcUrl(jdbcUrlBase64, "postgresql", POSTGRESQL_URL);
        log.info("postgresql jdbc connect");
        DriverManager.getConnection(jdbcUrl);
    }

    @RequestMapping("/db2")
    public void db2(String jdbcUrlBase64) throws Exception{
        Class.forName("com.ibm.db2.jcc.DB2Driver");
        String jdbcUrl = requireSafeJdbcUrl(jdbcUrlBase64, "db2", DB2_URL);
        log.info("db2 jdbc connect");
        DriverManager.getConnection(jdbcUrl);
    }
}
