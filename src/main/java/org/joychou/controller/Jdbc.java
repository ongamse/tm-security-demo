package org.joychou.controller;

import lombok.extern.slf4j.Slf4j;
import org.joychou.util.SafeBase64;
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

    private static final int MAX_JDBC_URL_B64_LENGTH = 4096;

    /**
     * <a href="https://github.com/JoyChou93/java-sec-code/wiki/CVE-2022-21724">CVE-2022-21724</a>
     */
    @RequestMapping("/postgresql")
    public void postgresql(String jdbcUrlBase64) throws Exception{
        byte[] b = SafeBase64.decode(jdbcUrlBase64, MAX_JDBC_URL_B64_LENGTH);
        String jdbcUrl = new String(b);
        log.info(jdbcUrl);
        DriverManager.getConnection(jdbcUrl);
    }

    @RequestMapping("/db2")
    public void db2(String jdbcUrlBase64) throws Exception{
        Class.forName("com.ibm.db2.jcc.DB2Driver");
        byte[] b = SafeBase64.decode(jdbcUrlBase64, MAX_JDBC_URL_B64_LENGTH);
        String jdbcUrl = new String(b);
        log.info(jdbcUrl);
        DriverManager.getConnection(jdbcUrl);
    }
}
