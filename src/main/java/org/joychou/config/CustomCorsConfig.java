package org.joychou.config;

import org.joychou.security.CustomCorsProcessor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.web.WebMvcRegistrationsAdapter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

@Configuration
public class CustomCorsConfig extends WebMvcRegistrationsAdapter {

    private static final Pattern ORIGIN_PATTERN = Pattern.compile("^https?://[A-Za-z0-9.-]+(:[0-9]{1,5})?$");

    /**
     * 设置cors origin白名单。区分http和https，并且默认不会拦截同域请求。
     */
    @Bean
    public WebMvcConfigurer corsConfigurer(
            @Value("${joychou.security.cors.allowed.origins:}") String[] corsAllowedOrigins) {
        // Keep only concrete scheme://host[:port] literals; invalid entries and "*" are dropped.
        final List<String> validOrigins = new ArrayList<>();
        if (corsAllowedOrigins != null) {
            for (String origin : corsAllowedOrigins) {
                String candidate = origin == null ? "" : origin.trim();
                if (ORIGIN_PATTERN.matcher(candidate).matches()) {
                    validOrigins.add(candidate);
                }
            }
        }
        final String[] allowOrigins = validOrigins.toArray(new String[0]);
        return new WebMvcConfigurerAdapter() {
            @Override
            public void addCorsMappings(CorsRegistry registry) {
                // No valid configured origin: no CORS mapping (fail closed).
                // Credentialed cross-origin requests (cookies) are not allowed.
                if (allowOrigins.length == 0) {
                    return;
                }
                // 为了支持一级域名，重写了checkOrigin
                registry.addMapping("/cors/sec/webMvcConfigurer") // /**表示所有路由path
                        .allowedOrigins(allowOrigins)
                        .allowedMethods("GET", "POST")
                        .allowedHeaders("Content-Type", "X-Requested-With", "Accept")
                        .allowCredentials(false);
            }
        };
    }


    @Override
    public RequestMappingHandlerMapping getRequestMappingHandlerMapping() {
        return new CustomRequestMappingHandlerMapping();
    }


    /**
     * 自定义Cors处理器，重写了checkOrigin
     * 自定义校验origin，支持一级域名校验 && 多级域名
     */
    private static class CustomRequestMappingHandlerMapping extends RequestMappingHandlerMapping {
        private CustomRequestMappingHandlerMapping() {
            setCorsProcessor(new CustomCorsProcessor());
        }
    }
}
