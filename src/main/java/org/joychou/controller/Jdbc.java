package org.joychou.controller;

import lombok.extern.slf4j.Slf4j;
import org.joychou.security.ssrf.SafeUrl;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.sql.DriverManager;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Jdbc Attack @2023.04
 */
@Slf4j
@RestController
@RequestMapping("/jdbc")
public class Jdbc {

    private static final String POSTGRESQL_PREFIX = "jdbc:postgresql://";
    private static final String DB2_PREFIX = "jdbc:db2://";

    // Selector: host[:port]/database. Anything after the database name is treated as connection
    // properties and only allowlisted, plain properties are accepted (no socketFactory, sslfactory,
    // authenticationPluginClassName, loggerFile, clientRerouteServerListJNDIName, pluginName, ...).
    private static final Pattern SELECTOR = Pattern.compile(
            "(\\[[0-9A-Fa-f:.]+\\]|[A-Za-z0-9.-]+)(?::([0-9]{1,5}))?/([A-Za-z0-9_]{1,63})([?;:].*)?",
            Pattern.DOTALL);

    // lower case request key -> canonical driver property name
    private static final Map<String, String> POSTGRESQL_ALLOWED_PARAMS = allowed(
            "user", "password", "ssl", "sslmode", "connectTimeout", "loginTimeout",
            "socketTimeout", "ApplicationName", "currentSchema");
    private static final Map<String, String> DB2_ALLOWED_PARAMS = allowed(
            "user", "password", "sslConnection", "loginTimeout", "connectTimeout", "readOnly");

    private static final int POSTGRESQL_DEFAULT_PORT = 5432;
    private static final int DB2_DEFAULT_PORT = 50000;

    private static Map<String, String> allowed(String... names) {
        Map<String, String> m = new HashMap<>();
        for (String n : names) {
            m.put(n.toLowerCase(Locale.ROOT), n);
        }
        return m;
    }

    /**
     * A jdbc target that is built server side: the driver prefix is a constant, the host is the
     * validated (public) resolved address, the port and database name are validated, and the
     * connection properties are allowlisted and passed as {@link Properties}, never concatenated
     * into the url.
     */
    static final class JdbcTarget {
        final String url;
        final Properties props;

        JdbcTarget(String url, Properties props) {
            this.url = url;
            this.props = props;
        }
    }

    /**
     * Validate a jdbc selector from the user and build the jdbc url from constants.
     */
    static JdbcTarget buildJdbcTarget(String requested, String prefix, int defaultPort,
                                      Map<String, String> allowedParams) {
        if (requested == null) {
            throw new IllegalArgumentException("Illegal jdbc url");
        }
        String selector = requested;
        if (selector.regionMatches(true, 0, prefix, 0, prefix.length())) {
            selector = selector.substring(prefix.length());
        }
        Matcher m = SELECTOR.matcher(selector);
        if (!m.matches()) {
            throw new IllegalArgumentException("Illegal jdbc url");
        }

        int port = defaultPort;
        if (m.group(2) != null) {
            port = Integer.parseInt(m.group(2));
            if (port < 1 || port > 65535) {
                throw new IllegalArgumentException("Illegal jdbc url port");
            }
        }

        // Resolve once and connect to the validated address, so there is no second DNS lookup.
        String hostLiteral;
        try {
            InetAddress address = SafeUrl.resolveExternal(m.group(1))[0];
            hostLiteral = address.getHostAddress();
            if (address instanceof Inet6Address) {
                int scope = hostLiteral.indexOf('%');
                hostLiteral = "[" + (scope < 0 ? hostLiteral : hostLiteral.substring(0, scope)) + "]";
            }
        } catch (java.io.IOException e) {
            throw new IllegalArgumentException("Illegal jdbc url host");
        }

        Properties props = new Properties();
        String rawParams = m.group(4);
        if (rawParams != null && rawParams.length() > 1) {
            String[] pairs = rawParams.substring(1).split(prefix.equals(DB2_PREFIX) ? "[;:]" : "&");
            for (String pair : pairs) {
                if (pair.isEmpty()) {
                    continue;
                }
                int eq = pair.indexOf('=');
                try {
                    String key = URLDecoder.decode(eq < 0 ? pair : pair.substring(0, eq), "UTF-8");
                    String value = eq < 0 ? "" : URLDecoder.decode(pair.substring(eq + 1), "UTF-8");
                    String canonical = allowedParams.get(key.trim().toLowerCase(Locale.ROOT));
                    if (canonical == null) {
                        throw new IllegalArgumentException("Illegal jdbc url parameter");
                    }
                    props.setProperty(canonical, value);
                } catch (java.io.UnsupportedEncodingException | IllegalArgumentException e) {
                    throw new IllegalArgumentException("Illegal jdbc url parameter");
                }
            }
        }

        String url = prefix + hostLiteral + ":" + port + "/" + m.group(3);
        return new JdbcTarget(url, props);
    }

    /**
     * <a href="https://github.com/JoyChou93/java-sec-code/wiki/CVE-2022-21724">CVE-2022-21724</a>
     */
    @RequestMapping("/postgresql")
    public void postgresql(String jdbcUrlBase64) throws Exception{
        byte[] b = java.util.Base64.getDecoder().decode(jdbcUrlBase64);
        JdbcTarget target = buildJdbcTarget(new String(b, StandardCharsets.UTF_8), POSTGRESQL_PREFIX,
                POSTGRESQL_DEFAULT_PORT, POSTGRESQL_ALLOWED_PARAMS);
        log.info("Opening validated jdbc connection");
        DriverManager.getConnection(target.url, target.props);
    }

    @RequestMapping("/db2")
    public void db2(String jdbcUrlBase64) throws Exception{
        Class.forName("com.ibm.db2.jcc.DB2Driver");
        byte[] b = java.util.Base64.getDecoder().decode(jdbcUrlBase64);
        JdbcTarget target = buildJdbcTarget(new String(b, StandardCharsets.UTF_8), DB2_PREFIX,
                DB2_DEFAULT_PORT, DB2_ALLOWED_PARAMS);
        log.info("Opening validated jdbc connection");
        DriverManager.getConnection(target.url, target.props);
    }
}
