package org.joychou.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.nio.charset.StandardCharsets;
import java.sql.DriverManager;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Properties;

/**
 * Jdbc Attack @2023.04
 *
 * <p>The request never supplies (any part of) the jdbc url or the credentials. It only supplies the
 * name of a server side configured target; the connection url is always the configured value and
 * the credentials come from the server side configuration.</p>
 */
@Slf4j
@RestController
@RequestMapping("/jdbc")
public class Jdbc {

    @Value("${joychou.jdbc.postgresql.targets:default=jdbc:postgresql://localhost:5432/postgres}")
    private String[] postgresqlTargets;

    @Value("${joychou.jdbc.db2.targets:default=jdbc:db2://localhost:50000/sample}")
    private String[] db2Targets;

    @Value("${joychou.jdbc.username:}")
    private String jdbcUsername;

    @Value("${joychou.jdbc.password:}")
    private String jdbcPassword;

    /**
     * Parse the configured "name=jdbc-url" entries (server side configuration only).
     */
    private static Map<String, String> configuredTargets(String[] entries, String prefix) {
        Map<String, String> targets = new LinkedHashMap<>();
        if (entries == null) {
            return targets;
        }
        for (String e : entries) {
            String entry = e.trim();
            int eq = entry.indexOf('=');
            if (eq <= 0) {
                continue;
            }
            String name = entry.substring(0, eq).trim();
            String url = entry.substring(eq + 1).trim();
            // only accept the expected driver for this endpoint
            if (!name.isEmpty() && url.startsWith(prefix)) {
                targets.put(name, url);
            }
        }
        return targets;
    }

    /**
     * Select a configured jdbc url by the name that the user requested. The returned string is the
     * configured map value, never the request string.
     */
    private static String selectTarget(Map<String, String> targets, String requestedName) {
        if (requestedName != null) {
            for (Map.Entry<String, String> target : targets.entrySet()) {
                if (target.getKey().equals(requestedName.trim())) {
                    return target.getValue();
                }
            }
        }
        throw new IllegalArgumentException("Illegal jdbc target");
    }

    /**
     * Credentials come from the server side configuration only.
     */
    private Properties serverSideCredentials() {
        Properties props = new Properties();
        if (jdbcUsername != null && !jdbcUsername.isEmpty()) {
            props.setProperty("user", jdbcUsername);
        }
        if (jdbcPassword != null && !jdbcPassword.isEmpty()) {
            props.setProperty("password", jdbcPassword);
        }
        return props;
    }

    private static String decodeSelector(String jdbcUrlBase64) {
        if (jdbcUrlBase64 == null) {
            throw new IllegalArgumentException("Illegal jdbc target");
        }
        byte[] b = java.util.Base64.getDecoder().decode(jdbcUrlBase64);
        return new String(b, StandardCharsets.UTF_8);
    }

    /**
     * <a href="https://github.com/JoyChou93/java-sec-code/wiki/CVE-2022-21724">CVE-2022-21724</a>
     *
     * @param jdbcUrlBase64 base64 of the name of a configured target
     */
    @RequestMapping("/postgresql")
    public void postgresql(String jdbcUrlBase64) throws Exception{
        String url = selectTarget(configuredTargets(postgresqlTargets, "jdbc:postgresql://"),
                decodeSelector(jdbcUrlBase64));
        log.info("Opening configured jdbc connection");
        DriverManager.getConnection(url, serverSideCredentials());
    }

    @RequestMapping("/db2")
    public void db2(String jdbcUrlBase64) throws Exception{
        Class.forName("com.ibm.db2.jcc.DB2Driver");
        String url = selectTarget(configuredTargets(db2Targets, "jdbc:db2://"),
                decodeSelector(jdbcUrlBase64));
        log.info("Opening configured jdbc connection");
        DriverManager.getConnection(url, serverSideCredentials());
    }
}
