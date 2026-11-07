package org.joychou.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.regex.Pattern;


/**
 * Solve can't get value in filter by @Value when not using embed tomcat.
 *
 * @author JoyChou @2019-07-24
 */
@Component // 注解@Component表明WebConfig类将被SpringIoC容器扫描装配，并且Bean名称为webConfig
public class WebConfig {

    private static String[] callbacks;
    private static Boolean jsonpReferCheckEnabled = false;
    private static String[] jsonpRefererHost;
    private static String[] referWhitelist;
    private static String[] referUris;
    private static Boolean referSecEnabled = false;
    private static String businessCallback;
    private static ArrayList<String> safeDomains = new ArrayList<>();
    private static ArrayList<String> blockDomains = new ArrayList<>();
    private static ArrayList<String> ssrfSafeDomains = new ArrayList<>();
    private static ArrayList<String> ssrfBlockDomains = new ArrayList<>();
    private static ArrayList<String> ssrfBlockIps = new ArrayList<>();

    // Exact scheme://host[:port] origins; no wildcard, no "null".
    private static final Pattern CORS_ORIGIN_PATTERN = Pattern.compile(
            "^https?://[A-Za-z0-9.-]{1,253}(?::[0-9]{1,5})?$");
    private static volatile Set<String> corsAllowedOrigins = Collections.emptySet();

    /**
     * Server side CORS origin allowlist (joychou.security.cors.allowed-origins). Empty by default,
     * which means no cross origin caller is allowed (fail closed).
     */
    @Value("${joychou.security.cors.allowed-origins:}")
    public void setCorsAllowedOrigins(String[] origins) {
        WebConfig.corsAllowedOrigins = parseCorsOrigins(origins);
    }

    public static Set<String> getCorsAllowedOrigins() {
        return corsAllowedOrigins;
    }

    /**
     * Keep only well formed exact origins ("*", "null" and anything else is dropped).
     *
     * @param origins raw configured values
     * @return unmodifiable set of exact origins
     */
    public static Set<String> parseCorsOrigins(String[] origins) {
        Set<String> result = new LinkedHashSet<>();
        if (origins != null) {
            for (String origin : origins) {
                if (origin == null) {
                    continue;
                }
                String trimmed = origin.trim();
                if (CORS_ORIGIN_PATTERN.matcher(trimmed).matches()) {
                    result.add(trimmed);
                }
            }
        }
        return Collections.unmodifiableSet(result);
    }

    /**
     * application.properties里object自动转jsonp的referer校验开关
     *
     * @param jsonpReferCheckEnabled jsonp校验开关
     */
    @Value("${joychou.security.jsonp.referer.check.enabled}")
    public void setJsonpReferCheckEnabled(Boolean jsonpReferCheckEnabled) {
        WebConfig.jsonpReferCheckEnabled = jsonpReferCheckEnabled;
    }

    public static Boolean getJsonpReferCheckEnabled() {
        return jsonpReferCheckEnabled;
    }


    @Value("${joychou.security.jsonp.callback}")
    public void setJsonpCallbacks(String[] callbacks) {
        WebConfig.callbacks = callbacks;
    }

    public static String[] getJsonpCallbacks() {
        return callbacks;
    }


    @Value("${joychou.security.referer.enabled}")
    public void setReferSecEnabled(Boolean referSecEnabled) {
        WebConfig.referSecEnabled = referSecEnabled;
    }

    public static Boolean getReferSecEnabled() {
        return referSecEnabled;
    }


    @Value("${joychou.security.referer.host}")
    public void setReferWhitelist(String[] referWhitelist) {
        WebConfig.referWhitelist = referWhitelist;
    }

    public static String[] getReferWhitelist() {
        return referWhitelist;
    }


    @Value("${joychou.security.referer.uri}")
    public void setReferUris(String[] referUris) {
        WebConfig.referUris = referUris;
    }

    public static String[] getReferUris() {
        return referUris;
    }


    @Value("${joychou.business.callback}")
    public void setBusinessCallback(String businessCallback) {
        WebConfig.businessCallback = businessCallback;
    }

    public static String getBusinessCallback() {
        return businessCallback;
    }


    void setSafeDomains(ArrayList<String> safeDomains) {
        WebConfig.safeDomains = safeDomains;
    }

    public static ArrayList<String> getSafeDomains() {
        return safeDomains;
    }


    void setBlockDomains(ArrayList<String> blockDomains) {
        WebConfig.blockDomains = blockDomains;
    }

    public static ArrayList<String> getBlockDomains() {
        return blockDomains;
    }


    void setSsrfSafeDomains(ArrayList<String> ssrfSafeDomains) {
        WebConfig.ssrfSafeDomains = ssrfSafeDomains;
    }

    public static ArrayList<String> getSsrfSafeDomains() {
        return ssrfSafeDomains;
    }


    void setSsrfBlockDomains(ArrayList<String> ssrfBlockDomains) {
        WebConfig.ssrfBlockDomains = ssrfBlockDomains;
    }

    public static ArrayList<String> getSsrfBlockDomainsDomains() {
        return ssrfBlockDomains;
    }


    void setSsrfBlockIps(ArrayList<String> ssrfBlockIps) {
        WebConfig.ssrfBlockIps = ssrfBlockIps;
    }

    public static ArrayList<String> getSsrfBlockIps() {
        return ssrfBlockIps;
    }
}