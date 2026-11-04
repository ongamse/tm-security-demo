package org.joychou.controller;

import lombok.extern.slf4j.Slf4j;
import org.joychou.security.ssrf.SSRFChecker;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.nio.charset.StandardCharsets;
import java.sql.DriverManager;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
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
     * <a href="https://github.com/JoyChou93/java-sec-code/wiki/CVE-2022-21724">CVE-2022-21724</a>
     */
    // jdbc:postgresql://host[:port]/database[?key=value&...]
    private static final Pattern POSTGRESQL_URL = Pattern.compile(
            "^jdbc:postgresql://([A-Za-z0-9.-]+)(?::([0-9]{1,5}))?/[A-Za-z0-9_-]+(?:\\?([A-Za-z0-9_=&.-]*))?$");

    // jdbc:db2://host[:port]/database  (no ":key=value;" driver properties)
    private static final Pattern DB2_URL = Pattern.compile(
            "^jdbc:db2://([A-Za-z0-9.-]+)(?::([0-9]{1,5}))?/[A-Za-z0-9_-]+$");

    // Driver properties that cannot load classes or touch files/urls.
    private static final Set<String> POSTGRESQL_PARAMS = new HashSet<String>(Arrays.asList(
            "ssl", "sslmode", "connecttimeout", "sockettimeout", "applicationname"));

    // Database ports that may be contacted (postgresql 5432/5433, db2 50000). Default port when omitted.
    private static final Set<String> ALLOWED_DB_PORTS = new HashSet<String>(Arrays.asList(
            "5432", "5433", "50000"));

    // Dangerous driver properties that are always rejected, whatever the driver.
    private static final String[] DANGEROUS_PROPS = {
            "autodeserialize", "allowloadlocalinfile", "allowurlinlocalinfile", "queryinterceptors",
            "statementinterceptors", "socketfactory", "sslfactory", "loggerfile", "loggerlevel",
            "authenticationpluginclassname", "sslhostnameverifier", "sslpasswordcallback",
            "sslpassword", "sslcert", "sslkey", "sslrootcert"};

    /**
     * Allowlist the JDBC url: only the expected driver scheme, a plain host that resolves to public
     * addresses only (no loopback, link-local, private, metadata) and safe driver properties.
     *
     * @return the validated jdbc url
     * @throws IllegalArgumentException if the url is not allowed
     */
    private static String checkJdbcUrl(String jdbcUrl, Pattern pattern, boolean checkParams) {
        Matcher m = jdbcUrl == null ? null : pattern.matcher(jdbcUrl);
        if (m == null || !m.matches() || !SSRFChecker.isSafeOutboundHost(m.group(1))) {
            throw new IllegalArgumentException("Illegal jdbc url");
        }
        // port allowlist (no userinfo is possible: the patterns above do not allow '@')
        if (m.group(2) != null && !ALLOWED_DB_PORTS.contains(m.group(2))) {
            throw new IllegalArgumentException("Illegal jdbc url port");
        }
        String lower = jdbcUrl.toLowerCase();
        for (String bad : DANGEROUS_PROPS) {
            if (lower.contains(bad)) {
                throw new IllegalArgumentException("Illegal jdbc url parameter");
            }
        }
        if (checkParams && m.groupCount() >= 3 && m.group(3) != null && !m.group(3).isEmpty()) {
            for (String kv : m.group(3).split("&")) {
                String key = kv.split("=", 2)[0].toLowerCase();
                if (!POSTGRESQL_PARAMS.contains(key)) {
                    throw new IllegalArgumentException("Illegal jdbc url parameter");
                }
            }
        }
        return jdbcUrl;
    }

    @RequestMapping("/postgresql")
    public void postgresql(String jdbcUrlBase64) throws Exception{
        byte[] b = java.util.Base64.getDecoder().decode(jdbcUrlBase64);
        String jdbcUrl = checkJdbcUrl(new String(b, StandardCharsets.UTF_8), POSTGRESQL_URL, true);
        log.info("Connecting to validated jdbc url");
        DriverManager.getConnection(jdbcUrl);
    }

    @RequestMapping("/db2")
    public void db2(String jdbcUrlBase64) throws Exception{
        Class.forName("com.ibm.db2.jcc.DB2Driver");
        byte[] b = java.util.Base64.getDecoder().decode(jdbcUrlBase64);
        String jdbcUrl = checkJdbcUrl(new String(b, StandardCharsets.UTF_8), DB2_URL, false);
        log.info("Connecting to validated jdbc url");
        DriverManager.getConnection(jdbcUrl);
    }
}
