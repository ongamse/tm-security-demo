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
    // Server-side table: index = input char (ASCII), value = the char built here, or 0 if not allowed.
    // Allowed database name chars are [A-Za-z0-9_].
    private static final char[] DB_NAME_TABLE = new char[128];

    static {
        for (char c = 'A'; c <= 'Z'; c++) {
            DB_NAME_TABLE[c] = c;
        }
        for (char c = 'a'; c <= 'z'; c++) {
            DB_NAME_TABLE[c] = c;
        }
        for (char c = '0'; c <= '9'; c++) {
            DB_NAME_TABLE[c] = c;
        }
        DB_NAME_TABLE['_'] = '_';
    }

    /** Rebuilds the database name from the server-side table; returns null on any disallowed char. */
    private static String rebuildDbName(String raw) {
        if (raw == null) {
            return null;
        }
        StringBuilder sb = new StringBuilder(raw.length());
        for (int i = 0; i < raw.length(); i++) {
            char in = raw.charAt(i);
            char safe = in < DB_NAME_TABLE.length ? DB_NAME_TABLE[in] : 0;
            if (safe == 0) {
                return null;
            }
            sb.append(safe);
        }
        return sb.toString();
    }

    private static String requireSafeJdbcUrl(String jdbcUrlBase64, String driverPrefix, Pattern allowed) {
        String jdbcUrl = new String(java.util.Base64.getDecoder().decode(jdbcUrlBase64),
                java.nio.charset.StandardCharsets.UTF_8);
        Matcher m = allowed.matcher(jdbcUrl);
        if (!m.matches()) {
            throw new IllegalArgumentException("Illegal jdbc url");
        }
        // The host must be an exact member of the server-side allowlist and resolve to public
        // addresses only; the allowlist's own entry is used, never the request text.
        String allowedHost = SSRFChecker.allowlistedOutboundHost(m.group(1));
        if (allowedHost == null) {
            throw new IllegalArgumentException("Illegal jdbc url");
        }
        int port = -1;
        if (m.group(2) != null) {
            port = Integer.parseInt(m.group(2));
            if (port < 1 || port > 65535) {
                throw new IllegalArgumentException("Illegal jdbc url");
            }
        }
        String dbName = rebuildDbName(m.group(3));
        if (dbName == null || dbName.isEmpty()) {
            throw new IllegalArgumentException("Illegal jdbc url");
        }
        // Re-construct the url from the fixed driver prefix, allowlisted host, numeric port and
        // a database name re-built from a server-side alphabet.
        return driverPrefix + allowedHost + (port >= 0 ? ":" + port : "") + "/" + dbName;
    }

    @RequestMapping("/postgresql")
    public void postgresql(String jdbcUrlBase64) throws Exception{
        String jdbcUrl = requireSafeJdbcUrl(jdbcUrlBase64, "jdbc:postgresql://", POSTGRESQL_URL);
        log.info("postgresql jdbc connect");
        DriverManager.getConnection(jdbcUrl);
    }

    @RequestMapping("/db2")
    public void db2(String jdbcUrlBase64) throws Exception{
        Class.forName("com.ibm.db2.jcc.DB2Driver");
        String jdbcUrl = requireSafeJdbcUrl(jdbcUrlBase64, "jdbc:db2://", DB2_URL);
        log.info("db2 jdbc connect");
        DriverManager.getConnection(jdbcUrl);
    }
}
