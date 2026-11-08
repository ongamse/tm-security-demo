package org.joychou.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.DriverManager;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Jdbc Attack @2023.04
 *
 * <p>The connection target is never taken from the request. The Base64 parameter is only a lookup
 * key: it must equal the name of a server-side profile (or the configured url of that profile)
 * and the connection is opened with the server-owned jdbc url of the profile. The urls come from
 * the environment (<code>JSC_JDBC_URL_POSTGRESQL</code>, <code>JSC_JDBC_URL_DB2</code>); a driver
 * without a configured url is not available.</p>
 */
@Slf4j
@RestController
@RequestMapping("/jdbc")
public class Jdbc {

    private static final String PROFILE_DEFAULT = "default";

    /**
     * CVE-2022-21724 target: only the server-configured jdbc urls (profile name to url) may be used.
     */
    private static Map<String, String> profiles(String envName) {
        String configured = System.getenv(envName);
        if (configured == null || configured.trim().isEmpty()) {
            return Collections.emptyMap();
        }
        Map<String, String> map = new LinkedHashMap<>();
        map.put(PROFILE_DEFAULT, configured.trim());
        return map;
    }

    /**
     * Select the server-owned jdbc url for the (Base64 encoded) key. The request value is only
     * compared with the allowlist entries; the returned string is always an allowlist constant.
     *
     * @return server-owned jdbc url, or null when the key is unknown
     */
    private static String select(Map<String, String> profiles, String jdbcUrlBase64) {
        if (jdbcUrlBase64 == null) {
            return null;
        }
        String key;
        try {
            key = new String(java.util.Base64.getDecoder().decode(jdbcUrlBase64), StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            return null;
        }
        for (Map.Entry<String, String> entry : profiles.entrySet()) {
            if (entry.getKey().equals(key) || entry.getValue().equals(key)) {
                return entry.getValue();
            }
        }
        return null;
    }

    private static ResponseEntity<String> connect(String envName, String jdbcUrlBase64) throws Exception {
        String serverUrl = select(profiles(envName), jdbcUrlBase64);
        if (serverUrl == null) {
            log.warn("Unknown jdbc profile");
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body("Illegal jdbc profile");
        }
        log.info("Connecting with configured jdbc profile");
        try (Connection connection = DriverManager.getConnection(serverUrl)) {
            return ResponseEntity.ok(connection.isClosed() ? "closed" : "connected");
        }
    }

    @RequestMapping("/postgresql")
    public ResponseEntity<String> postgresql(String jdbcUrlBase64) throws Exception {
        return connect("JSC_JDBC_URL_POSTGRESQL", jdbcUrlBase64);
    }

    @RequestMapping("/db2")
    public ResponseEntity<String> db2(String jdbcUrlBase64) throws Exception {
        Class.forName("com.ibm.db2.jcc.DB2Driver");
        return connect("JSC_JDBC_URL_DB2", jdbcUrlBase64);
    }
}
