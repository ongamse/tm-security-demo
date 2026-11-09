package org.joychou.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.nio.charset.StandardCharsets;
import java.sql.DriverManager;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * Jdbc Attack @2023.04
 */
@Slf4j
@RestController
@RequestMapping("/jdbc")
public class Jdbc {

    /**
     * Server-side allowlists of databases the endpoints may connect to. The request value is only a
     * lookup key (a short name, or the base64 of the exact connection string); the JDBC URL handed to
     * the driver is always the constant stored in these tables, so no part of the request ever reaches
     * DriverManager and connection properties (socketFactory, loggerFile, ...) cannot be injected.
     */
    private static final Map<String, String> POSTGRESQL_TARGETS;
    private static final Map<String, String> DB2_TARGETS;

    static {
        Map<String, String> pg = new HashMap<String, String>();
        pg.put("postgres", "jdbc:postgresql://127.0.0.1:5432/postgres");
        POSTGRESQL_TARGETS = Collections.unmodifiableMap(pg);

        Map<String, String> db2 = new HashMap<String, String>();
        db2.put("sample", "jdbc:db2://127.0.0.1:50000/sample");
        DB2_TARGETS = Collections.unmodifiableMap(db2);
    }

    /**
     * Resolve the untrusted request value to a server-side constant JDBC URL.
     *
     * @param key   untrusted lookup key supplied by the client
     * @param table the allowlist for this endpoint
     * @return the constant JDBC URL stored in the table
     * @throws IllegalArgumentException when the key is not allowlisted (fail closed)
     */
    private static String resolveJdbcTarget(String key, Map<String, String> table) {
        if (key != null) {
            for (Map.Entry<String, String> entry : table.entrySet()) {
                if (entry.getKey().equals(key)) {
                    return entry.getValue();
                }
            }
            // also accept the base64 of an allowlisted connection string (decoded and compared to the constants)
            try {
                String decoded = new String(java.util.Base64.getDecoder().decode(key), StandardCharsets.UTF_8);
                for (String constant : table.values()) {
                    if (constant.equals(decoded)) {
                        return constant;
                    }
                }
            } catch (IllegalArgumentException e) {
                // not base64: fall through, fail closed
            }
        }
        throw new IllegalArgumentException("Illegal jdbc url");
    }

    /**
     * <a href="https://github.com/JoyChou93/java-sec-code/wiki/CVE-2022-21724">CVE-2022-21724</a>
     */
    @RequestMapping("/postgresql")
    public void postgresql(String jdbcUrlBase64) throws Exception{
        String jdbcUrl = resolveJdbcTarget(jdbcUrlBase64, POSTGRESQL_TARGETS);
        log.info("jdbc target allowlisted, length={}", jdbcUrl.length());
        DriverManager.getConnection(jdbcUrl);
    }

    @RequestMapping("/db2")
    public void db2(String jdbcUrlBase64) throws Exception{
        Class.forName("com.ibm.db2.jcc.DB2Driver");
        String jdbcUrl = resolveJdbcTarget(jdbcUrlBase64, DB2_TARGETS);
        log.info("jdbc target allowlisted, length={}", jdbcUrl.length());
        DriverManager.getConnection(jdbcUrl);
    }
}
