package org.joychou.controller;

import lombok.extern.slf4j.Slf4j;
import org.joychou.security.SecurityUtil;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.net.URI;
import java.sql.DriverManager;

/**
 * Jdbc Attack @2023.04
 */
@Slf4j
@RestController
@RequestMapping("/jdbc")
public class Jdbc {

    /**
     * Only plain <code>jdbc:&lt;subprotocol&gt;://host[:port]/db</code> URLs to an external host are accepted.
     * Connection properties (query string / ';' properties) are rejected because they can load
     * arbitrary classes (e.g. socketFactory, sslfactory) or redirect the connection.
     */
    private static void validateJdbcUrl(String jdbcUrl, String subProtocol) {
        String prefix = "jdbc:" + subProtocol + "://";
        if (jdbcUrl == null || !jdbcUrl.toLowerCase().startsWith(prefix)) {
            throw new IllegalArgumentException("Illegal jdbc url");
        }
        if (jdbcUrl.indexOf('?') != -1 || jdbcUrl.indexOf(';') != -1 || jdbcUrl.indexOf('\\') != -1) {
            throw new IllegalArgumentException("Illegal jdbc url");
        }
        // Reuse the SSRF defence: host must be parseable and must not resolve to an internal address.
        String httpUrl = "http://" + jdbcUrl.substring(prefix.length());
        URI uri;
        try {
            uri = new URI(httpUrl);
        } catch (Exception e) {
            throw new IllegalArgumentException("Illegal jdbc url");
        }
        if (uri.getHost() == null || uri.getUserInfo() != null || !SecurityUtil.checkSSRFWithoutRedirect(httpUrl)) {
            throw new IllegalArgumentException("Illegal jdbc url");
        }
    }

    /**
     * <a href="https://github.com/JoyChou93/java-sec-code/wiki/CVE-2022-21724">CVE-2022-21724</a>
     */
    @RequestMapping("/postgresql")
    public void postgresql(String jdbcUrlBase64) throws Exception{
        byte[] b = java.util.Base64.getDecoder().decode(jdbcUrlBase64);
        String jdbcUrl = new String(b);
        validateJdbcUrl(jdbcUrl, "postgresql");
        log.info(jdbcUrl);
        DriverManager.getConnection(jdbcUrl);
    }

    @RequestMapping("/db2")
    public void db2(String jdbcUrlBase64) throws Exception{
        Class.forName("com.ibm.db2.jcc.DB2Driver");
        byte[] b = java.util.Base64.getDecoder().decode(jdbcUrlBase64);
        String jdbcUrl = new String(b);
        validateJdbcUrl(jdbcUrl, "db2");
        log.info(jdbcUrl);
        DriverManager.getConnection(jdbcUrl);
    }
}
