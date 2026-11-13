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
     * Only the expected jdbc scheme, no connection properties (e.g. socketFactory in CVE-2022-21724)
     * and a host that is on the SSRF host allowlist are accepted.
     *
     * @param jdbcUrl the decoded jdbc url
     * @param scheme  expected scheme without the jdbc: prefix, e.g. postgresql
     * @return the validated jdbc url
     * @throws IllegalArgumentException if the url is not allowed
     */
    private static String checkJdbcUrl(String jdbcUrl, String scheme) {
        if (jdbcUrl == null) {
            throw new IllegalArgumentException("Illegal jdbc url");
        }
        // Strict jdbc:<scheme>://host[:port][/db]; anything else (userinfo, properties, ?, ;, \) is rejected.
        Matcher m = Pattern.compile("^jdbc:" + Pattern.quote(scheme)
                + "://([A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?)(:[0-9]{1,5})?(/[A-Za-z0-9_]{1,63})?$")
                .matcher(jdbcUrl);
        if (!m.matches()) {
            throw new IllegalArgumentException("Illegal jdbc url");
        }
        String host = m.group(1);
        if (!SecurityUtil.checkSSRFByWhitehosts("http://" + host + "/")) {
            throw new IllegalArgumentException("Illegal jdbc host");
        }
        // Rebuild the url only from the validated components.
        return "jdbc:" + scheme + "://" + host + (m.group(3) == null ? "" : m.group(3))
                + (m.group(4) == null ? "" : m.group(4));
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
