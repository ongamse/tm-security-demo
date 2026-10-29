package org.joychou.controller;

import org.joychou.security.LogSanitizer;
import lombok.extern.slf4j.Slf4j;
import org.joychou.util.CookieUtils;
import org.joychou.util.JwtUtils;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;


/**
 *
 */
@Slf4j
@RestController
@RequestMapping("/jwt")
public class Jwt {

    private static final String COOKIE_NAME = "USER_COOKIE";
    /**
     * http://localhost:8080/jwt/createToken
     * Create jwt token and set token to cookies.
     *
     * @author JoyChou 2022-09-20
     */
    @GetMapping("/createToken")
    public String createToken(HttpServletResponse response, HttpServletRequest request) {
        String loginUser = request.getUserPrincipal().getName();
        log.info("Current login user is {}", LogSanitizer.clean(loginUser));

        CookieUtils.deleteCookie(response, COOKIE_NAME);
        String token = JwtUtils.generateTokenByJavaJwt(loginUser);
        Cookie cookie = new Cookie(COOKIE_NAME, token);

        cookie.setMaxAge(86400);    // 1 DAY
        cookie.setPath("/");
        cookie.setSecure(true);
        cookie.setHttpOnly(true);
        response.addCookie(cookie);
        return "Add jwt token cookie successfully. Cookie name is USER_COOKIE";
    }


    /**
     * http://localhost:8080/jwt/getName
     * Get nickname from USER_COOKIE
     *
     * @author JoyChou 2022-09-20
     * @param user_cookie cookie
     * @return nickname
     */
    @GetMapping("/getName")
    public ResponseEntity<String> getNickname(@CookieValue(COOKIE_NAME) String user_cookie) {
        String nickname = JwtUtils.getNicknameByJavaJwt(user_cookie);
        String encoded = encodeEntities(nickname);
        return ResponseEntity.ok()
                .contentType(MediaType.parseMediaType("text/plain;charset=UTF-8"))
                .header("X-Content-Type-Options", "nosniff")
                .body("Current jwt user is " + encoded);
    }

    /**
     * Build a new string in which every character outside [A-Za-z0-9 ._-]
     * is replaced by a numeric character reference.
     */
    private static String encodeEntities(String origin) {
        if (origin == null) {
            return "null";
        }
        StringBuilder sb = new StringBuilder(origin.length() * 2);
        int i = 0;
        while (i < origin.length()) {
            int cp = origin.codePointAt(i);
            i += Character.charCount(cp);
            boolean letter = (cp >= 'A' && cp <= 'Z') || (cp >= 'a' && cp <= 'z');
            boolean digit = cp >= '0' && cp <= '9';
            if (letter || digit) {
                sb.append((char) cp);
            } else if (cp == ' ' || cp == '.' || cp == '_' || cp == '-') {
                sb.append((char) cp);
            } else {
                sb.append("&#").append(cp).append(';');
            }
        }
        return sb.toString();
    }

}
