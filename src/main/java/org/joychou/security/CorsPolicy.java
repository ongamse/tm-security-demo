package org.joychou.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Single CORS policy shared by the controllers, the servlet filter and the Spring MVC CORS mappings.
 *
 * Origins are matched EXACTLY (scheme://host[:port]) against a server-owned constant set. The
 * Access-Control-Allow-Origin value is always the matching constant, never the request string, and
 * Access-Control-Allow-Credentials is never emitted. No wildcard, no suffix match and
 * no "null" origin. Additional origins can be supplied with the environment variable
 * JSC_CORS_ALLOWED_ORIGINS (comma separated, each entry must be an exact http(s) origin).
 */
public final class CorsPolicy {

    private static final Logger logger = LoggerFactory.getLogger(CorsPolicy.class);

    public static final String ENV_ALLOWED_ORIGINS = "JSC_CORS_ALLOWED_ORIGINS";

    private static final Pattern EXACT_ORIGIN = Pattern.compile(
            "^https?://[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?(:[0-9]{1,5})?$");

    private static final Set<String> DEFAULT_ORIGINS = Collections.unmodifiableSet(new LinkedHashSet<>(
            Arrays.asList("https://www.joychou.org", "https://joychou.org", "https://test.joychou.org")));

    private static final Set<String> ALLOWED_ORIGINS = buildAllowedOrigins();

    private CorsPolicy() {
    }

    private static Set<String> buildAllowedOrigins() {
        Set<String> origins = new LinkedHashSet<>(DEFAULT_ORIGINS);
        String extra = System.getenv(ENV_ALLOWED_ORIGINS);
        if (extra != null) {
            for (String entry : extra.split(",")) {
                String candidate = entry.trim();
                if (candidate.isEmpty()) {
                    continue;
                }
                if (EXACT_ORIGIN.matcher(candidate).matches()) {
                    origins.add(candidate);
                } else {
                    logger.warn("Ignoring invalid CORS origin entry in " + ENV_ALLOWED_ORIGINS);
                }
            }
        }
        return Collections.unmodifiableSet(origins);
    }

    /**
     * @return the exact allowed origins as an array (for CorsRegistry / CorsConfiguration)
     */
    public static String[] allowedOriginsArray() {
        return ALLOWED_ORIGINS.toArray(new String[0]);
    }

    /**
     * @param origin untrusted Origin header value, may be null
     * @return the matching constant from the allowlist, or null (also for the string "null")
     */
    public static String match(String origin) {
        return SecurityUtil.matchAllowlisted(origin, ALLOWED_ORIGINS);
    }

    /**
     * Apply the CORS response headers for the request Origin.
     * Always adds Vary: Origin. If the Origin exactly matches the allowlist, sets
     * Access-Control-Allow-Origin to the matching constant; otherwise no CORS header is emitted.
     * Credentialed cross-origin access is never granted by this policy.
     *
     * @param request  current request
     * @param response current response
     * @return true if the origin was allowed, false otherwise (no CORS headers were set)
     */
    public static boolean apply(HttpServletRequest request, HttpServletResponse response) {
        response.addHeader("Vary", "Origin");
        String allowed = match(request.getHeader("Origin"));
        if (allowed == null) {
            return false;
        }
        response.setHeader("Access-Control-Allow-Origin", allowed);
        return true;
    }
}
