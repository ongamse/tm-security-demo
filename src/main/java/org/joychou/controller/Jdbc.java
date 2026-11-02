package org.joychou.controller;

import lombok.extern.slf4j.Slf4j;
import org.joychou.security.SafeUrl;
import org.joychou.security.ssrf.SSRFChecker;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.nio.charset.StandardCharsets;
import java.sql.DriverManager;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * Jdbc Attack @2023.04
 */
@Slf4j
@RestController
@RequestMapping("/jdbc")
public class Jdbc {

    /** Database ports that a user supplied jdbc url may use (-1 means the driver default). */
    private static final Set<Integer> ALLOWED_PORTS = new HashSet<>(Arrays.asList(5432, 50000));

    /** Trusted host, database and property sets; every jdbc url below is built from these constants only. */
    private static final String TRUSTED_HOST = "db.joychou.org";
    private static final String[] DATABASES = {"postgres", "appdb"};
    private static final String[] POSTGRESQL_PROPERTY_SETS = {"", "?ssl=true", "?sslmode=require"};

    /**
     * Closed set of trusted PostgreSQL connections: key = "host/database[?property set]" (the only thing
     * taken from the request); value = the complete constant jdbc url.
     */
    private static final Map<String, String> POSTGRESQL_URLS;

    /** Closed set of trusted DB2 connections: key = "host/database"; value = the complete constant jdbc url. */
    private static final Map<String, String> DB2_URLS;

    static {
        Map<String, String> pg = new HashMap<>();
        Map<String, String> db2 = new HashMap<>();
        for (String db : DATABASES) {
            for (String props : POSTGRESQL_PROPERTY_SETS) {
                pg.put(TRUSTED_HOST + "/" + db + props,
                        "jdbc:postgresql://" + TRUSTED_HOST + ":5432/" + db + props);
            }
            db2.put(TRUSTED_HOST + "/" + db, "jdbc:db2://" + TRUSTED_HOST + ":50000/" + db);
        }
        POSTGRESQL_URLS = Collections.unmodifiableMap(pg);
        DB2_URLS = Collections.unmodifiableMap(db2);
    }

    /**
     * Select a trusted jdbc url for a user supplied jdbc url. The request text is only parsed to find the
     * lookup key (host, database, property set) in the closed set; the returned url is always one of the
     * map's constants and no request text (path, query, values) is concatenated into it.
     *
     * @param jdbcUrl  the decoded jdbc url
     * @param prefix   the required prefix, such as <code>jdbc:postgresql://</code>
     * @param trusted  lookup key -> complete constant jdbc url
     * @return the constant jdbc url
     * @throws IllegalArgumentException if the url is not in the closed set
     */
    static String validateJdbcUrl(String jdbcUrl, String prefix, Map<String, String> trusted) {
        if (jdbcUrl == null || !jdbcUrl.startsWith(prefix)) {
            throw new IllegalArgumentException("Illegal jdbc url");
        }
        // jdbc:xxx://host:port/db?params -> parsed into immutable components (no URI/URL from raw text)
        SafeUrl parsed = SafeUrl.parse(jdbcUrl.substring("jdbc:".length()));
        if (parsed == null || parsed.getUserInfo() != null || parsed.getRawFragment() != null) {
            throw new IllegalArgumentException("Illegal jdbc url");
        }
        if (parsed.getPort() != -1 && !ALLOWED_PORTS.contains(parsed.getPort())) {
            throw new IllegalArgumentException("Illegal jdbc port");
        }
        if (!SSRFChecker.isSafeHost(parsed.getHost())) {
            throw new IllegalArgumentException("Illegal jdbc host");
        }
        String constantUrl = trusted.get(parsed.getHost() + parsed.getFile());
        if (constantUrl == null) {
            throw new IllegalArgumentException("Illegal jdbc target");
        }
        return constantUrl;
    }

    /**
     * <a href="https://github.com/JoyChou93/java-sec-code/wiki/CVE-2022-21724">CVE-2022-21724</a>
     */
    @RequestMapping("/postgresql")
    public void postgresql(String jdbcUrlBase64) throws Exception{
        byte[] b = java.util.Base64.getDecoder().decode(jdbcUrlBase64);
        String jdbcUrl = new String(b, StandardCharsets.UTF_8);
        String safeJdbcUrl = validateJdbcUrl(jdbcUrl, "jdbc:postgresql://", POSTGRESQL_URLS);
        DriverManager.getConnection(safeJdbcUrl);
    }

    @RequestMapping("/db2")
    public void db2(String jdbcUrlBase64) throws Exception{
        Class.forName("com.ibm.db2.jcc.DB2Driver");
        byte[] b = java.util.Base64.getDecoder().decode(jdbcUrlBase64);
        String jdbcUrl = new String(b, StandardCharsets.UTF_8);
        String safeJdbcUrl = validateJdbcUrl(jdbcUrl, "jdbc:db2://", DB2_URLS);
        DriverManager.getConnection(safeJdbcUrl);
    }
}
