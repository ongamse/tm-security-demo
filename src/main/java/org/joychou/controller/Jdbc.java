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
import java.util.regex.Pattern;

/**
 * Jdbc Attack @2023.04
 */
@Slf4j
@RestController
@RequestMapping("/jdbc")
public class Jdbc {

    /** Database ports that a user supplied jdbc url may use (-1 means the driver default). */
    private static final Set<Integer> ALLOWED_PORTS = new HashSet<>(Arrays.asList(5432, 50000));

    /**
     * Connection properties accepted in a user supplied PostgreSQL jdbc url. Class loading / file / socket
     * factory properties (socketFactory, sslfactory, loggerFile, authenticationPluginClassName, ...) are rejected.
     */
    private static final Set<String> POSTGRESQL_ALLOWED_PARAMS = new HashSet<>(Arrays.asList(
            "user", "password", "ssl", "sslmode", "connecttimeout", "logintimeout", "sockettimeout",
            "applicationname"));

    /** Closed set of trusted PostgreSQL targets: host -> constant jdbc base url (no request text). */
    private static final Map<String, String> POSTGRESQL_TARGETS;

    /** Closed set of trusted DB2 targets: host -> constant jdbc base url (no request text). */
    private static final Map<String, String> DB2_TARGETS;

    static {
        Map<String, String> pg = new HashMap<>();
        pg.put("db.joychou.org", "jdbc:postgresql://db.joychou.org:5432");
        POSTGRESQL_TARGETS = Collections.unmodifiableMap(pg);

        Map<String, String> db2 = new HashMap<>();
        db2.put("db.joychou.org", "jdbc:db2://db.joychou.org:50000");
        DB2_TARGETS = Collections.unmodifiableMap(db2);
    }

    private static final Pattern DB_NAME = Pattern.compile("^/[A-Za-z0-9_]{1,63}$");
    private static final Pattern PARAM_VALUE = Pattern.compile("^[A-Za-z0-9_.\\-]{1,64}$");

    /**
     * Validate a user supplied jdbc url and build the connection url from constants: the scheme prefix must
     * match, the host must be a single public host that is a key of the trusted target map, and there must be
     * no user info. The returned url consists of the map's constant base url (host and port), a database name
     * that matches a strict pattern and, for PostgreSQL only, allow-listed property names (constants) with
     * strictly validated values.
     *
     * @param jdbcUrl        the decoded jdbc url
     * @param prefix         the required prefix, such as <code>jdbc:postgresql://</code>
     * @param targets        trusted host -> constant jdbc base url
     * @param allowedParams  allowed query parameter names (lower case); null rejects any query/properties
     * @return the jdbc url rebuilt from constants and validated components
     * @throws IllegalArgumentException if the url is not allowed
     */
    static String validateJdbcUrl(String jdbcUrl, String prefix, Map<String, String> targets,
                                  Set<String> allowedParams) {
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
        // closed set: the host/port part of the connection url is the map's constant
        String base = targets.get(parsed.getHost());
        if (base == null) {
            throw new IllegalArgumentException("Illegal jdbc host");
        }
        // database name only (this also rejects DB2 style ':' / ';' properties after the name)
        String path = parsed.getRawPath();
        if (!DB_NAME.matcher(path).matches()) {
            throw new IllegalArgumentException("Illegal jdbc database");
        }
        StringBuilder result = new StringBuilder(base).append(path);
        String query = parsed.getRawQuery();
        if (query != null) {
            if (allowedParams == null) {
                throw new IllegalArgumentException("Illegal jdbc properties");
            }
            char separator = '?';
            for (String pair : query.split("&", -1)) {
                String[] kv = pair.split("=", 2);
                String name = null;
                for (String allowed : allowedParams) { // the property name is the allow-list constant
                    if (allowed.equalsIgnoreCase(kv[0])) {
                        name = allowed;
                        break;
                    }
                }
                if (name == null || kv.length != 2 || !PARAM_VALUE.matcher(kv[1]).matches()) {
                    throw new IllegalArgumentException("Illegal jdbc property");
                }
                result.append(separator).append(name).append('=').append(kv[1]);
                separator = '&';
            }
        }
        return result.toString();
    }

    /**
     * <a href="https://github.com/JoyChou93/java-sec-code/wiki/CVE-2022-21724">CVE-2022-21724</a>
     */
    @RequestMapping("/postgresql")
    public void postgresql(String jdbcUrlBase64) throws Exception{
        byte[] b = java.util.Base64.getDecoder().decode(jdbcUrlBase64);
        String jdbcUrl = new String(b, StandardCharsets.UTF_8);
        String safeJdbcUrl = validateJdbcUrl(jdbcUrl, "jdbc:postgresql://", POSTGRESQL_TARGETS,
                POSTGRESQL_ALLOWED_PARAMS);
        DriverManager.getConnection(safeJdbcUrl);
    }

    @RequestMapping("/db2")
    public void db2(String jdbcUrlBase64) throws Exception{
        Class.forName("com.ibm.db2.jcc.DB2Driver");
        byte[] b = java.util.Base64.getDecoder().decode(jdbcUrlBase64);
        String jdbcUrl = new String(b, StandardCharsets.UTF_8);
        String safeJdbcUrl = validateJdbcUrl(jdbcUrl, "jdbc:db2://", DB2_TARGETS, null);
        DriverManager.getConnection(safeJdbcUrl);
    }
}
