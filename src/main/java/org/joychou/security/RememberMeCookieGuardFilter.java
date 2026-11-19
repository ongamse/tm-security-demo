package org.joychou.security;

import org.springframework.security.web.authentication.rememberme.AbstractRememberMeServices;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;
import java.util.regex.Pattern;

/**
 * Spring Security's rememberMe services Base64-decode the attacker-controlled
 * remember-me cookie (CVE-2026-114938). This filter runs before the
 * RememberMeAuthenticationFilter and hides a remember-me cookie that is oversized
 * or outside the Base64 / URL-encoded alphabet, so such input is never decoded
 * (the request is treated as having no remember-me cookie).
 */
public class RememberMeCookieGuardFilter extends OncePerRequestFilter {

    private static final int MAX_COOKIE_LENGTH = 4096;
    private static final Pattern ALLOWED = Pattern.compile("^[A-Za-z0-9+/_%=-]*$");

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {
        Cookie[] cookies = request.getCookies();
        if (cookies == null || Arrays.stream(cookies).noneMatch(RememberMeCookieGuardFilter::isBad)) {
            chain.doFilter(request, response);
            return;
        }
        final Cookie[] filtered = Arrays.stream(cookies)
                .filter(c -> !isBad(c))
                .toArray(Cookie[]::new);
        chain.doFilter(new HttpServletRequestWrapper(request) {
            @Override
            public Cookie[] getCookies() {
                return filtered.length == 0 ? null : filtered.clone();
            }
        }, response);
    }

    private static boolean isBad(Cookie c) {
        if (!AbstractRememberMeServices.SPRING_SECURITY_REMEMBER_ME_COOKIE_KEY.equals(c.getName())) {
            return false;
        }
        String v = c.getValue();
        return v == null || v.length() > MAX_COOKIE_LENGTH || !ALLOWED.matcher(v).matches();
    }
}
