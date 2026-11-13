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
     * Only the expected jdbc scheme, no connection properties (e.g. socketFactory in CVE-2022-21724)
     * and a host that is on the SSRF host allowlist are accepted.
     *
     * @param jdbcUrl the decoded jdbc url
     * @param scheme  expected scheme without the jdbc: prefix, e.g. postgresql
     * @return the validated jdbc url
     * @throws IllegalArgumentException if the url is not allowed
     */
    private static String checkJdbcUrl(String jdbcUrl, String scheme) {
        String prefix = "jdbc:" + scheme + "://";
        if (jdbcUrl == null || !jdbcUrl.startsWith(prefix) || jdbcUrl.indexOf('?') != -1
                || jdbcUrl.indexOf(';') != -1 || jdbcUrl.indexOf('\\') != -1) {
            throw new IllegalArgumentException("Illegal jdbc url");
        }
        try {
            URI uri = new URI(jdbcUrl.substring("jdbc:".length()));
            String host = uri.getHost();
            if (host == null || !SecurityUtil.checkSSRFByWhitehosts("http://" + host + "/")) {
                throw new IllegalArgumentException("Illegal jdbc host");
            }
        } catch (java.net.URISyntaxException e) {
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
        String jdbcUrl = checkJdbcUrl(new String(b), "postgresql");
        log.info(jdbcUrl);
        DriverManager.getConnection(jdbcUrl);
    }

    @RequestMapping("/db2")
    public void db2(String jdbcUrlBase64) throws Exception{
        Class.forName("com.ibm.db2.jcc.DB2Driver");
        byte[] b = java.util.Base64.getDecoder().decode(jdbcUrlBase64);
        String jdbcUrl = checkJdbcUrl(new String(b), "db2");
        log.info(jdbcUrl);
        DriverManager.getConnection(jdbcUrl);
    }
}
