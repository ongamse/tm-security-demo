package org.joychou.security;

import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.DefaultCorsProcessor;

public class CustomCorsProcessor extends DefaultCorsProcessor {

    private static final Logger logger = LoggerFactory.getLogger(CustomCorsProcessor.class);


    /**
     * 跨域请求，会通过此方法检测请求源是否被允许
     *
     * @param config        CORS 配置
     * @param requestOrigin 请求源
     * @return 如果请求源被允许，返回请求源；否则返回 null
     */
    @Override
    protected String checkOrigin(CorsConfiguration config, String requestOrigin) {

        if (StringUtils.isBlank(requestOrigin)) {
            return null;
        }

        // 支持原装的域名配置: the returned value is the configured constant, never the request string
        java.util.List<String> configured = config.getAllowedOrigins();
        if (configured != null) {
            for (String allowed : configured) {
                if ("*".equals(allowed)) {
                    // wildcard is never combined with credentials
                    if (!Boolean.TRUE.equals(config.getAllowCredentials())) {
                        return "*";
                    }
                } else if (allowed != null && allowed.equals(requestOrigin)) {
                    return allowed;
                }
            }
        }

        return customCheckOrigin(requestOrigin);
    }


    /**
     * 自定义校验requestOrigin
     */
    private String customCheckOrigin(String requestOrigin) {

        String safeOrigin = SecurityUtil.checkCorsOrigin(requestOrigin);
        if (safeOrigin != null) {
            logger.info("[+] Origin: "  + safeOrigin );
            return safeOrigin;
        }
        logger.error("[-] Origin: " + requestOrigin );
        return null;
    }


}