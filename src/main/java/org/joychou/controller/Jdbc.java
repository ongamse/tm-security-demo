package org.joychou.controller;

import lombok.extern.slf4j.Slf4j;
import org.joychou.security.SafeUrl;
import org.joychou.security.ssrf.SSRFChecker;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.nio.charset.StandardCharsets;
import java.sql.DriverManager;
import java.util.Arrays;
import java.util.HashSet;
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

    /**
     * Connection properties accepted in a user supplied PostgreSQL jdbc url. Class loading / file / socket
     * factory properties (socketFactory, sslfactory, loggerFile, authenticationPluginClassName, ...) are rejected.
     */
    private static final Set<String> POSTGRESQL_ALLOWED_PARAMS = new HashSet<>(Arrays.asList(
            "user", "password", "ssl", "sslmode", "connecttimeout", "logintimeout", "sockettimeout",
            "applicationname"));

    /**
     * Validate a user supplied jdbc url: the scheme prefix must match, the host must be a single
     * public host (no loopback/private/link-local/metadata addresses), and there must be no user info.
     *
     * @param jdbcUrl        the decoded jdbc url
     * @param prefix         the required prefix, such as <code>jdbc:postgresql://</code>
     * @param allowedParams  allowed query parameter names (lower case); null rejects any query/properties
     * @return the jdbc url rebuilt from the validated components
     * @throws IllegalArgumentException if the url is not allowed
     */
    static String validateJdbcUrl(String jdbcUrl, String prefix, Set<String> allowedParams) {
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
        String query = parsed.getRawQuery();
        if (query != null) {
            if (allowedParams == null) {
                throw new IllegalArgumentException("Illegal jdbc properties");
            }
            for (String pair : query.split("&")) {
                String key = pair.split("=", 2)[0].toLowerCase();
                if (!allowedParams.contains(key)) {
                    throw new IllegalArgumentException("Illegal jdbc property");
                }
            }
        }
        // DB2 style properties are appended with ':' or ';' after the database name.
        String path = parsed.getRawPath();
        if (allowedParams == null && (path.contains(";") || path.contains(":"))) {
            throw new IllegalArgumentException("Illegal jdbc properties");
        }
        // the connection url is rebuilt from the validated components
        return "jdbc:" + parsed.toExternalForm();
    }

    /**
     * <a href="https://github.com/JoyChou93/java-sec-code/wiki/CVE-2022-21724">CVE-2022-21724</a>
     */
    @RequestMapping("/postgresql")
    public void postgresql(String jdbcUrlBase64) throws Exception{
        byte[] b = java.util.Base64.getDecoder().decode(jdbcUrlBase64);
        String jdbcUrl = new String(b, StandardCharsets.UTF_8);
        String safeJdbcUrl = validateJdbcUrl(jdbcUrl, "jdbc:postgresql://", POSTGRESQL_ALLOWED_PARAMS);
        DriverManager.getConnection(safeJdbcUrl);
    }

    @RequestMapping("/db2")
    public void db2(String jdbcUrlBase64) throws Exception{
        Class.forName("com.ibm.db2.jcc.DB2Driver");
        byte[] b = java.util.Base64.getDecoder().decode(jdbcUrlBase64);
        String jdbcUrl = new String(b, StandardCharsets.UTF_8);
        String safeJdbcUrl = validateJdbcUrl(jdbcUrl, "jdbc:db2://", null);
        DriverManager.getConnection(safeJdbcUrl);
    }
}
