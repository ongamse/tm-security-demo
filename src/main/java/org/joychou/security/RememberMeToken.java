package org.joychou.security;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.regex.Pattern;

/**
 * Signed rememberMe token. Replaces Java native deserialization of the rememberMe cookie: the
 * cookie carries only a plain username string plus an HMAC-SHA256 over it, so no request-derived
 * bytes are ever passed to an ObjectInputStream.
 *
 * Format: base64url(username UTF-8) + "." + base64url(HMAC-SHA256(secret, base64url(username)))
 *
 * The server-side secret is read from the system property "rememberme.secret" or the environment
 * variable REMEMBER_ME_SECRET. When no secret is configured, every token is rejected (fail closed).
 */
public final class RememberMeToken {

    private static final String HMAC_ALGORITHM = "HmacSHA256";
    private static final int MAX_TOKEN_LENGTH = 512;
    private static final int MIN_SECRET_LENGTH = 16;
    private static final Pattern USERNAME = Pattern.compile("^[A-Za-z0-9_.@-]{1,64}$");

    private RememberMeToken() {
    }

    private static byte[] secret() {
        String configured = System.getProperty("rememberme.secret", System.getenv("REMEMBER_ME_SECRET"));
        if (configured == null || configured.length() < MIN_SECRET_LENGTH) {
            return null;
        }
        return configured.getBytes(StandardCharsets.UTF_8);
    }

    private static byte[] hmac(byte[] key, String data) throws GeneralSecurityException {
        Mac mac = Mac.getInstance(HMAC_ALGORITHM);
        mac.init(new SecretKeySpec(key, HMAC_ALGORITHM));
        return mac.doFinal(data.getBytes(StandardCharsets.US_ASCII));
    }

    /** Creates a signed token for the username; throws if no secret is configured or the name is invalid. */
    public static String create(String username) throws GeneralSecurityException {
        byte[] key = secret();
        if (key == null) {
            throw new IllegalStateException("rememberMe secret is not configured");
        }
        if (username == null || !USERNAME.matcher(username).matches()) {
            throw new IllegalArgumentException("Illegal username");
        }
        String payload = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(username.getBytes(StandardCharsets.UTF_8));
        String sig = Base64.getUrlEncoder().withoutPadding().encodeToString(hmac(key, payload));
        return payload + "." + sig;
    }

    /**
     * Verifies the token (constant-time signature compare) and returns the username,
     * or null when the token is missing, malformed, unsigned, or the secret is not configured.
     */
    public static String verify(String token) {
        if (token == null || token.length() > MAX_TOKEN_LENGTH) {
            return null;
        }
        byte[] key = secret();
        if (key == null) {
            return null;
        }
        int dot = token.indexOf('.');
        if (dot <= 0 || dot != token.lastIndexOf('.') || dot == token.length() - 1) {
            return null;
        }
        String payload = token.substring(0, dot);
        String sig = token.substring(dot + 1);
        try {
            byte[] given = Base64.getUrlDecoder().decode(sig);
            byte[] expected = hmac(key, payload);
            if (!MessageDigest.isEqual(expected, given)) {
                return null;
            }
            String username = new String(Base64.getUrlDecoder().decode(payload), StandardCharsets.UTF_8);
            return USERNAME.matcher(username).matches() ? username : null;
        } catch (IllegalArgumentException | GeneralSecurityException e) {
            return null;
        }
    }
}
