package org.joychou.controller;

import lombok.extern.slf4j.Slf4j;
import org.joychou.security.SecurityUtil;
import org.joychou.util.SafeBase64;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.sql.DriverManager;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

/**
 * Jdbc Attack @2023.04
 */
@Slf4j
@RestController
@RequestMapping("/jdbc")
public class Jdbc {

    private static final int MAX_JDBC_URL_B64_LENGTH = 4096;

    /**
     * <a href="https://github.com/JoyChou93/java-sec-code/wiki/CVE-2022-21724">CVE-2022-21724</a>
     */
    private static final Set<String> POSTGRESQL_ALLOWED_PARAMS = Collections.unmodifiableSet(new HashSet<String>(
            Arrays.asList("user", "password", "ssl", "sslmode", "connectTimeout", "loginTimeout",
                    "socketTimeout", "currentSchema")));

    @RequestMapping("/postgresql")
    public void postgresql(String jdbcUrlBase64) throws Exception{
        byte[] b = SafeBase64.decode(jdbcUrlBase64, MAX_JDBC_URL_B64_LENGTH);
        String jdbcUrl = new String(b);
        if (!SecurityUtil.isSafeJdbcUrl(jdbcUrl, "jdbc:postgresql://", POSTGRESQL_ALLOWED_PARAMS)) {
            throw new IllegalArgumentException("Illegal jdbc url");
        }
        log.info(jdbcUrl);
        DriverManager.getConnection(jdbcUrl);
    }

    @RequestMapping("/db2")
    public void db2(String jdbcUrlBase64) throws Exception{
        Class.forName("com.ibm.db2.jcc.DB2Driver");
        byte[] b = SafeBase64.decode(jdbcUrlBase64, MAX_JDBC_URL_B64_LENGTH);
        String jdbcUrl = new String(b);
        // DB2 driver properties are appended after the database name; accept no extra properties.
        if (!SecurityUtil.isSafeJdbcUrl(jdbcUrl, "jdbc:db2://", Collections.<String>emptySet())) {
            throw new IllegalArgumentException("Illegal jdbc url");
        }
        log.info(jdbcUrl);
        DriverManager.getConnection(jdbcUrl);
    }
}
