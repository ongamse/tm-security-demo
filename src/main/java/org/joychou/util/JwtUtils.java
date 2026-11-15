package org.joychou.util;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.extern.slf4j.Slf4j;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Date;

@Slf4j
public class JwtUtils {

    private static final long EXPIRE = 1440 * 60 * 1000;  // 1440 Minutes, 1 DAY
    private static final int RANDOM_KEY_BYTES = 32;

    /**
     * HMAC signing key. Loaded from the JWT_SECRET environment variable (or the jwt.secret system
     * property). When neither is configured a random per-process key is generated, so tokens are
     * only valid for the lifetime of this JVM. No key is ever hardcoded in the source.
     */
    private static final byte[] SECRET_KEY = loadSecretKey();

    private static byte[] loadSecretKey() {
        String configured = System.getenv("JWT_SECRET");
        if (configured == null || configured.isEmpty()) {
            configured = System.getProperty("jwt.secret");
        }
        if (configured != null && !configured.isEmpty()) {
            return configured.getBytes(StandardCharsets.UTF_8);
        }
        log.warn("JWT_SECRET is not configured, using a random per-process signing key");
        byte[] random = new byte[RANDOM_KEY_BYTES];
        new SecureRandom().nextBytes(random);
        return random;
    }

    /**
     * Generate JWT Token by jjwt (last update time: Jul 05, 2018)
     *
     * @author JoyChou 2022-09-20
     * @param userId userid
     * @return token
     */
    public static String generateTokenByJjwt(String userId) {
        return Jwts.builder()
                .setHeaderParam("typ", "JWT")   // header
                .setHeaderParam("alg", "HS256")     // header
                .setIssuedAt(new Date())    // token发布时间
                .setExpiration(new Date(System.currentTimeMillis() + EXPIRE))   // token过期时间
                .claim("userid", userId)
                .signWith(SignatureAlgorithm.HS256, SECRET_KEY)
                .compact();
    }

    public static String getUserIdFromJjwtToken(String token) {
        try {
            Claims claims = Jwts.parser().setSigningKey(SECRET_KEY).parseClaimsJws(token).getBody();
            return (String)claims.get("userid");
        } catch (Exception e) {
            return e.toString();
        }
    }

    /**
     * Generate jwt token by java-jwt.
     *
     * @author JoyChou 2022-09-20
     * @param nickname nickname
     * @return jwt token
     */
    public static String generateTokenByJavaJwt(String nickname) {
        return JWT.create()
                .withClaim("nickname", nickname)
                .withExpiresAt(new Date(System.currentTimeMillis() + EXPIRE))
                .withIssuedAt(new Date())
                .sign(Algorithm.HMAC256(SECRET_KEY));
    }


    /**
     * Verify JWT Token
     * @param token token
     * @return Valid token returns true. Invalid token returns false.
     */
    public static Boolean verifyTokenByJavaJwt(String token) {
        return verifyAndDecodeByJavaJwt(token) != null;
    }

    /**
     * Verify the signature (HS256 only, so unsigned / alg=none tokens are rejected), the expiry
     * and return the verified token.
     *
     * @param token token
     * @return the verified token, or null when the token is invalid (fail closed).
     */
    private static DecodedJWT verifyAndDecodeByJavaJwt(String token) {
        try {
            Algorithm algorithm = Algorithm.HMAC256(SECRET_KEY);
            JWTVerifier verifier = JWT.require(algorithm).build();
            return verifier.verify(token);
        } catch (JWTVerificationException | IllegalArgumentException exception) {
            log.error(exception.toString());
            return null;
        }
    }


    public static String getNicknameByJavaJwt(String token) {
        // Only claims of the signature-verified token are used.
        DecodedJWT verified = verifyAndDecodeByJavaJwt(token);
        if (verified == null) {
            log.error("token is invalid");
            return null;
        }
        return verified.getClaim("nickname").asString();
    }


    public static void main(String[] args) {
        String jjwtToken = generateTokenByJjwt("10000");
        System.out.println(jjwtToken);
        System.out.println(getUserIdFromJjwtToken(jjwtToken));

        String token = generateTokenByJavaJwt("JoyChou");
        System.out.println(token);
        System.out.println(getNicknameByJavaJwt(token));
    }
}
