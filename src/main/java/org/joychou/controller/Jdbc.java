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
        String jdbcUrl = new String(b, java.nio.charset.StandardCharsets.UTF_8);
        // rebuilt from an allowlisted public host + allowlisted connection parameters only
        String allowedUrl = SecurityUtil.resolveAllowedPostgresqlJdbcUrl(jdbcUrl);
        if (allowedUrl == null) {
            log.warn("Illegal postgresql jdbc url rejected");
            return;
        }
        DriverManager.getConnection(allowedUrl);
    }

    @RequestMapping("/db2")
    public void db2(String jdbcUrlBase64) throws Exception{
        Class.forName("com.ibm.db2.jcc.DB2Driver");
        byte[] b = java.util.Base64.getDecoder().decode(jdbcUrlBase64);
        String jdbcUrl = new String(b, java.nio.charset.StandardCharsets.UTF_8);
        // rebuilt from an allowlisted public host + allowlisted connection properties only
        String allowedUrl = SecurityUtil.resolveAllowedDb2JdbcUrl(jdbcUrl);
        if (allowedUrl == null) {
            log.warn("Illegal db2 jdbc url rejected");
            return;
        }
        DriverManager.getConnection(allowedUrl);
    }
}
