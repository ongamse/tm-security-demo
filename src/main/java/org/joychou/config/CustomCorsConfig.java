package org.joychou.config;

import org.joychou.security.CustomCorsProcessor;
import org.springframework.boot.autoconfigure.web.WebMvcRegistrationsAdapter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

@Configuration
public class CustomCorsConfig extends WebMvcRegistrationsAdapter {

    /** Fixed server-side list of explicit origins (scheme://host); never "*". */
    private static final String[] ALLOWED_ORIGINS = {
            "https://joychou.org", "http://joychou.org", "http://test.joychou.me"};

    /**
     * 设置cors origin白名单。区分http和https，并且默认不会拦截同域请求。
     */
    @Bean
    public WebMvcConfigurer corsConfigurer() {
        return new WebMvcConfigurerAdapter() {
            @Override
            public void addCorsMappings(CorsRegistry registry) {
                // 为了支持一级域名，重写了checkOrigin
                // 显式配置origin白名单，不允许所有来源；CustomCorsProcessor会在此基础上额外校验一级域名
                // 固定的服务端常量白名单，不含通配符；不允许携带凭证(cookie)的跨域请求
                registry.addMapping("/cors/sec/webMvcConfigurer") // /**表示所有路由path
                        .allowedOrigins(ALLOWED_ORIGINS)
                        .allowedMethods("GET", "POST")
                        .allowedHeaders("Content-Type", "X-Requested-With", "X-CSRF-TOKEN")
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
