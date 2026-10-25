package org.joychou.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.sql.DriverManager;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Jdbc Attack @2023.04
 */
@Slf4j
@RestController
@RequestMapping("/jdbc")
public class Jdbc {

    // Allowlist of permitted JDBC URL prefixes
    private static final List<String> ALLOWED_JDBC_PREFIXES = Arrays.asList(
            "jdbc:postgresql://",
            "jdbc:db2://"
    );

    // Reject JDBC URLs containing dangerous parameters (socketFactory, sslfactory, etc.)
    private static final Pattern DANGEROUS_JDBC_PARAMS = Pattern.compile(
            "(socketFactory|socketFactoryArg|sslfactory|sslpasswordcallback|loggerLevel|loggerFile|authenticationPluginClassName)",
            Pattern.CASE_INSENSITIVE
    );

    /**
     * Validate a JDBC URL: must start with an allowed prefix and must not contain
     * dangerous connection properties.
     */
    private static void validateJdbcUrl(String jdbcUrl, String expectedPrefix) {
        if (jdbcUrl == null || !jdbcUrl.startsWith(expectedPrefix)) {
            throw new IllegalArgumentException("JDBC URL must start with " + expectedPrefix);
        }
        boolean prefixAllowed = false;
        for (String prefix : ALLOWED_JDBC_PREFIXES) {
            if (jdbcUrl.startsWith(prefix)) {
                prefixAllowed = true;
                break;
            }
        }
        if (!prefixAllowed) {
            throw new IllegalArgumentException("JDBC URL prefix is not in the allowlist");
        }
        if (DANGEROUS_JDBC_PARAMS.matcher(jdbcUrl).find()) {
            throw new IllegalArgumentException("JDBC URL contains disallowed parameters");
        }
    }

    /**
     * <a href="https://github.com/JoyChou93/java-sec-code/wiki/CVE-2022-21724">CVE-2022-21724</a>
     */
    @RequestMapping("/postgresql")
    public void postgresql(String jdbcUrlBase64) throws Exception{
        byte[] b = java.util.Base64.getDecoder().decode(jdbcUrlBase64);
        String jdbcUrl = new String(b);
        validateJdbcUrl(jdbcUrl, "jdbc:postgresql://");
        log.info(jdbcUrl);
        DriverManager.getConnection(jdbcUrl);
    }

    @RequestMapping("/db2")
    public void db2(String jdbcUrlBase64) throws Exception{
        Class.forName("com.ibm.db2.jcc.DB2Driver");
        byte[] b = java.util.Base64.getDecoder().decode(jdbcUrlBase64);
        String jdbcUrl = new String(b);
        validateJdbcUrl(jdbcUrl, "jdbc:db2://");
        log.info(jdbcUrl);
        DriverManager.getConnection(jdbcUrl);
    }
}
