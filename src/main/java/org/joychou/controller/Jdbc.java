package org.joychou.controller;

import lombok.extern.slf4j.Slf4j;
import org.joychou.security.ssrf.SSRFChecker;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.net.URI;
import java.net.URLDecoder;
import java.sql.DriverManager;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;

/**
 * Jdbc Attack @2023.04
 */
@Slf4j
@RestController
@RequestMapping("/jdbc")
public class Jdbc {

    private static final String POSTGRESQL_PREFIX = "jdbc:postgresql://";
    private static final String DB2_PREFIX = "jdbc:db2://";

    // Only plain connection properties are accepted. Properties that load classes or open
    // other resources (socketFactory, sslfactory, authenticationPluginClassName, loggerFile,
    // clientRerouteServerListJNDIName, pluginName, ...) are rejected.
    private static final Set<String> POSTGRESQL_ALLOWED_PARAMS = new HashSet<>(Arrays.asList(
            "user", "password", "ssl", "sslmode", "connecttimeout", "logintimeout",
            "sockettimeout", "applicationname", "currentschema"));
    private static final Set<String> DB2_ALLOWED_PARAMS = new HashSet<>(Arrays.asList(
            "user", "password", "sslconnection", "logintimeout", "connecttimeout", "readonly"));

    /**
     * Validate a jdbc url from the user: allowed driver prefix only, a single host that is not
     * internal / loopback / link-local, and only allowlisted connection properties.
     */
    static String checkJdbcUrl(String jdbcUrl, String prefix, Set<String> allowedParams) {
        if (jdbcUrl == null || !jdbcUrl.regionMatches(true, 0, prefix, 0, prefix.length())) {
            throw new IllegalArgumentException("Illegal jdbc url");
        }
        String rest = jdbcUrl.substring(prefix.length());
        String params = "";
        String paramSeparator = prefix.equals(DB2_PREFIX) ? ":" : "?";
        int hostEnd = rest.indexOf('/');
        if (hostEnd < 0) {
            throw new IllegalArgumentException("Illegal jdbc url");
        }
        int paramStart = rest.indexOf(paramSeparator, hostEnd);
        String path = paramStart < 0 ? rest.substring(hostEnd) : rest.substring(hostEnd, paramStart);
        if (paramStart >= 0) {
            params = rest.substring(paramStart + 1);
        }
        String hostPart = rest.substring(0, hostEnd);

        String host;
        try {
            URI uri = new URI("tcp://" + hostPart + path);
            host = uri.getHost();
            if (host == null || uri.getUserInfo() != null) {
                throw new IllegalArgumentException("Illegal jdbc url");
            }
        } catch (java.net.URISyntaxException e) {
            throw new IllegalArgumentException("Illegal jdbc url");
        }
        if (SSRFChecker.isInternalHost(host)) {
            throw new IllegalArgumentException("Illegal jdbc url host");
        }

        if (!params.isEmpty()) {
            String[] pairs = params.split(prefix.equals(DB2_PREFIX) ? ";" : "&");
            for (String pair : pairs) {
                if (pair.isEmpty()) {
                    continue;
                }
                String key = pair.indexOf('=') < 0 ? pair : pair.substring(0, pair.indexOf('='));
                try {
                    key = URLDecoder.decode(key, "UTF-8");
                } catch (Exception e) {
                    throw new IllegalArgumentException("Illegal jdbc url");
                }
                if (!allowedParams.contains(key.trim().toLowerCase(Locale.ROOT))) {
                    throw new IllegalArgumentException("Illegal jdbc url parameter");
                }
            }
        }
        return jdbcUrl;
    }

    /**
     * <a href="https://github.com/JoyChou93/java-sec-code/wiki/CVE-2022-21724">CVE-2022-21724</a>
     */
    @RequestMapping("/postgresql")
    public void postgresql(String jdbcUrlBase64) throws Exception{
        byte[] b = java.util.Base64.getDecoder().decode(jdbcUrlBase64);
        String jdbcUrl = checkJdbcUrl(new String(b), POSTGRESQL_PREFIX, POSTGRESQL_ALLOWED_PARAMS);
        log.info(jdbcUrl);
        DriverManager.getConnection(jdbcUrl);
    }

    @RequestMapping("/db2")
    public void db2(String jdbcUrlBase64) throws Exception{
        Class.forName("com.ibm.db2.jcc.DB2Driver");
        byte[] b = java.util.Base64.getDecoder().decode(jdbcUrlBase64);
        String jdbcUrl = checkJdbcUrl(new String(b), DB2_PREFIX, DB2_ALLOWED_PARAMS);
        log.info(jdbcUrl);
        DriverManager.getConnection(jdbcUrl);
    }
}
