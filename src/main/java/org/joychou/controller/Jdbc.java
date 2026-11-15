package org.joychou.controller;

import lombok.extern.slf4j.Slf4j;
import org.joychou.security.SecurityUtil;
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
     * Only plain jdbc:postgresql:// or jdbc:db2:// urls of the form host[:port]/database are accepted.
     * Query/property parts (socketFactory, sslfactory, loggerFile, ...) are rejected, and the host
     * must resolve to public addresses only.
     */
    private static final Pattern JDBC_URL = Pattern.compile(
            "^jdbc:(?:postgresql|db2)://([A-Za-z0-9.-]{1,253})(:[0-9]{1,5})?/[A-Za-z0-9_.-]{1,64}$");

    private static String validateJdbcUrl(String jdbcUrl) {
        Matcher m = JDBC_URL.matcher(jdbcUrl);
        if (!m.matches() || !SecurityUtil.checkSSRFResolved(
                "https://" + m.group(1) + (m.group(2) == null ? "" : m.group(2)))) {
            throw new IllegalArgumentException("Illegal jdbc url");
        }
        return jdbcUrl;
    }

    /**
     * <a href="https://github.com/JoyChou93/java-sec-code/wiki/CVE-2022-21724">CVE-2022-21724</a>
     */
    @RequestMapping("/postgresql")
    public void postgresql(String jdbcUrlBase64) throws Exception{
        byte[] b = java.util.Base64.getDecoder().decode(jdbcUrlBase64);
        String jdbcUrl = new String(b);
        DriverManager.getConnection(validateJdbcUrl(jdbcUrl));
    }

    @RequestMapping("/db2")
    public void db2(String jdbcUrlBase64) throws Exception{
        Class.forName("com.ibm.db2.jcc.DB2Driver");
        byte[] b = java.util.Base64.getDecoder().decode(jdbcUrlBase64);
        String jdbcUrl = new String(b);
        DriverManager.getConnection(validateJdbcUrl(jdbcUrl));
    }
}
