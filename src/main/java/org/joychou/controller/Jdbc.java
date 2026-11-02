package org.joychou.controller;

import lombok.extern.slf4j.Slf4j;
import org.joychou.security.ssrf.SSRFChecker;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.net.URI;
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
     * @throws IllegalArgumentException if the url is not allowed
     */
    static void validateJdbcUrl(String jdbcUrl, String prefix, Set<String> allowedParams) {
        if (jdbcUrl == null || !jdbcUrl.startsWith(prefix)) {
            throw new IllegalArgumentException("Illegal jdbc url");
        }
        try {
            // jdbc:xxx://host:port/db?params -> xxx://host:port/db?params
            URI uri = new URI(jdbcUrl.substring("jdbc:".length()));
            if (uri.getUserInfo() != null || !SSRFChecker.isSafeHost(uri.getHost())) {
                throw new IllegalArgumentException("Illegal jdbc host");
            }
            String query = uri.getRawQuery();
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
            String path = uri.getRawPath();
            if (allowedParams == null && path != null && (path.contains(";") || path.contains(":"))) {
                throw new IllegalArgumentException("Illegal jdbc properties");
            }
        } catch (java.net.URISyntaxException e) {
            throw new IllegalArgumentException("Illegal jdbc url");
        }
    }

    /**
     * <a href="https://github.com/JoyChou93/java-sec-code/wiki/CVE-2022-21724">CVE-2022-21724</a>
     */
    @RequestMapping("/postgresql")
    public void postgresql(String jdbcUrlBase64) throws Exception{
        byte[] b = java.util.Base64.getDecoder().decode(jdbcUrlBase64);
        String jdbcUrl = new String(b, StandardCharsets.UTF_8);
        validateJdbcUrl(jdbcUrl, "jdbc:postgresql://", POSTGRESQL_ALLOWED_PARAMS);
        DriverManager.getConnection(jdbcUrl);
    }

    @RequestMapping("/db2")
    public void db2(String jdbcUrlBase64) throws Exception{
        Class.forName("com.ibm.db2.jcc.DB2Driver");
        byte[] b = java.util.Base64.getDecoder().decode(jdbcUrlBase64);
        String jdbcUrl = new String(b, StandardCharsets.UTF_8);
        validateJdbcUrl(jdbcUrl, "jdbc:db2://", null);
        DriverManager.getConnection(jdbcUrl);
    }
}
