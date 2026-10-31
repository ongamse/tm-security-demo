package org.joychou.controller;

import lombok.extern.slf4j.Slf4j;
import org.joychou.security.ssrf.SSRFException;
import org.joychou.security.ssrf.SafeUrl;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.nio.charset.StandardCharsets;
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

    /** <code>jdbc:&lt;subprotocol&gt;://host[:port][/database]</code>, nothing else (no properties). */
    private static final Pattern JDBC_URL = Pattern.compile(
            "^jdbc:(postgresql|db2)://([A-Za-z0-9.-]{1,253}|\\[[0-9A-Fa-f:.]{2,45}\\])(?::([0-9]{1,5}))?(?:/([A-Za-z0-9_.-]{1,63}))?$");

    /** One allowlist entry: <code>host:port[/database]</code> (IPv6 host in brackets). */
    private static final Pattern ENDPOINT = Pattern.compile(
            "^([A-Za-z0-9.-]{1,253}|\\[[0-9A-Fa-f:.]{2,45}\\]):([0-9]{1,5})(?:/([A-Za-z0-9_.-]{1,63}))?$");

    /**
     * Find the operator configured endpoint that matches the requested host:port. The fixed list of
     * <code>host:port[/database]</code> endpoints (comma separated) comes from the system property
     * <code>jdbc.allowed.endpoints</code> or the environment variable <code>JDBC_ALLOWED_ENDPOINTS</code>.
     * Default deny: when nothing is configured, no endpoint is allowed. The returned matcher belongs to the
     * <b>configured</b> entry, so every component used afterwards comes from configuration, not from the request.
     */
    private static Matcher configuredEndpoint(String host, int port) {
        String configured = System.getProperty("jdbc.allowed.endpoints", System.getenv("JDBC_ALLOWED_ENDPOINTS"));
        if (configured == null || configured.trim().isEmpty()) {
            return null;
        }
        for (String entry : configured.split(",")) {
            Matcher e = ENDPOINT.matcher(entry.trim());
            if (e.matches() && e.group(1).equalsIgnoreCase(host) && Integer.parseInt(e.group(2)) == port) {
                return e;
            }
        }
        return null;
    }

    /**
     * Validate the untrusted jdbc url and build a new one from configured constants only. The raw decoded
     * value is never handed to the driver: the requested host and port only select an entry of the server-side
     * allowlist (<code>jdbc.allowed.endpoints</code>, default deny); the host, port and database of the
     * rebuilt url are taken from that configured entry. The configured host is resolved once and rejected
     * when it is loopback / link-local / site-local / any-local / multicast, and the rebuilt url points at
     * the resolved literal IP (so DNS rebinding cannot swap the destination). Connection properties
     * (query string / ';' properties) are impossible by construction because they can load arbitrary
     * classes (e.g. socketFactory, sslfactory) or redirect the connection.
     */
    private static String buildSafeJdbcUrl(String jdbcUrl, String subProtocol, int defaultPort) {
        if (jdbcUrl == null) {
            throw new IllegalArgumentException("Illegal jdbc url");
        }
        Matcher m = JDBC_URL.matcher(jdbcUrl);
        if (!m.matches() || !m.group(1).equals(subProtocol)) {
            throw new IllegalArgumentException("Illegal jdbc url");
        }
        int requestedPort = m.group(3) == null ? defaultPort : Integer.parseInt(m.group(3));
        Matcher endpoint = configuredEndpoint(m.group(2), requestedPort);
        if (endpoint == null) {
            throw new IllegalArgumentException("Illegal jdbc url");
        }
        // From here on only the configured entry is used.
        String configuredHost = endpoint.group(1);
        int port = Integer.parseInt(endpoint.group(2));
        if (port < 1 || port > 65535) {
            throw new IllegalArgumentException("Illegal jdbc url");
        }
        String database = endpoint.group(3);
        // A database named in the request must be the configured one.
        if (m.group(4) != null && !m.group(4).equals(database)) {
            throw new IllegalArgumentException("Illegal jdbc url");
        }
        SafeUrl target;
        try {
            // SafeUrl is only used to validate and resolve host:port; no http request is made.
            target = SafeUrl.parse("https://" + configuredHost + ":" + port + "/");
        } catch (SSRFException e) {
            throw new IllegalArgumentException("Illegal jdbc url");
        }
        StringBuilder safe = new StringBuilder("jdbc:").append(subProtocol).append("://")
                .append(target.getAddressLiteral()).append(':').append(port);
        // TLS is always required and added here as fixed, server-side constants (never from user input).
        if ("postgresql".equals(subProtocol)) {
            safe.append('/').append(database == null ? "" : database).append("?sslmode=verify-full");
        } else {
            if (database == null) {
                throw new IllegalArgumentException("Illegal jdbc url");
            }
            safe.append('/').append(database).append(":sslConnection=true;");
        }
        return safe.toString();
    }

    /**
     * <a href="https://github.com/JoyChou93/java-sec-code/wiki/CVE-2022-21724">CVE-2022-21724</a>
     */
    @RequestMapping("/postgresql")
    public void postgresql(String jdbcUrlBase64) throws Exception{
        byte[] b = java.util.Base64.getDecoder().decode(jdbcUrlBase64);
        String safeUrl = buildSafeJdbcUrl(new String(b, StandardCharsets.UTF_8), "postgresql", 5432);
        log.info("Connecting to validated jdbc endpoint");
        DriverManager.getConnection(safeUrl);
    }

    @RequestMapping("/db2")
    public void db2(String jdbcUrlBase64) throws Exception{
        Class.forName("com.ibm.db2.jcc.DB2Driver");
        byte[] b = java.util.Base64.getDecoder().decode(jdbcUrlBase64);
        String safeUrl = buildSafeJdbcUrl(new String(b, StandardCharsets.UTF_8), "db2", 50000);
        log.info("Connecting to validated jdbc endpoint");
        DriverManager.getConnection(safeUrl);
    }
}
