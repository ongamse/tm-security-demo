package org.joychou.controller;

import lombok.extern.slf4j.Slf4j;
import org.joychou.security.SecurityUtil;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.sql.DriverManager;

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
    @RequestMapping("/postgresql")
    public void postgresql(String jdbcUrlBase64) throws Exception{
        byte[] b = java.util.Base64.getDecoder().decode(jdbcUrlBase64);
        String jdbcUrl = new String(b);
        log.info("postgresql jdbc url received, length: {}", jdbcUrl.length());
        String safeUrl = SecurityUtil.safeJdbcUrl(jdbcUrl, "postgresql");
        if (safeUrl == null) {
            throw new IllegalArgumentException("Illegal jdbc url");
        }
        DriverManager.getConnection(safeUrl);
    }

    @RequestMapping("/db2")
    public void db2(String jdbcUrlBase64) throws Exception{
        Class.forName("com.ibm.db2.jcc.DB2Driver");
        byte[] b = java.util.Base64.getDecoder().decode(jdbcUrlBase64);
        String jdbcUrl = new String(b);
        log.info("db2 jdbc url received, length: {}", jdbcUrl.length());
        String safeUrl = SecurityUtil.safeJdbcUrl(jdbcUrl, "db2");
        if (safeUrl == null) {
            throw new IllegalArgumentException("Illegal jdbc url");
        }
        DriverManager.getConnection(safeUrl);
    }
}
