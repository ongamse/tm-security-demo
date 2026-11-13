package org.joychou.controller;

import lombok.extern.slf4j.Slf4j;
import org.joychou.security.SecurityUtil;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
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

    private static final String DB_NAME_ALPHABET =
            "/ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_";

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
        String candidate = m.group(1);
        if (!SecurityUtil.checkSSRFByWhitehosts("http://" + candidate + "/")) {
            throw new IllegalArgumentException("Illegal jdbc host");
        }
        // The host used for the connection comes only from the SSRF chokepoint (allowlisted, public address).
        String host;
        try {
            host = SecurityUtil.requireSafeUrl("https://" + candidate + "/").getHost();
        } catch (IOException e) {
            throw new IllegalArgumentException("Illegal jdbc host");
        }
        // Rebuild the url only from the validated components: allowlist-owned host, numeric port, db name
        // rebuilt character by character from a closed alphabet.
        StringBuilder safeUrl = new StringBuilder("jdbc:").append(scheme).append("://").append(host);
        if (m.group(3) != null) {
            int port = Integer.parseInt(m.group(3).substring(1));
            if (port < 1 || port > 65535) {
                throw new IllegalArgumentException("Illegal jdbc port");
            }
            safeUrl.append(':').append(port);
        }
        if (m.group(4) != null) {
            String db = SecurityUtil.rebuildFrom(m.group(4), DB_NAME_ALPHABET);
            if (db == null) {
                throw new IllegalArgumentException("Illegal jdbc database");
            }
            safeUrl.append(db);
        }
        return safeUrl.toString();
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
