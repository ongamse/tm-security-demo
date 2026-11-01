package org.joychou.security;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Base64;

/**
 * Authenticated rememberMe cookie value. No Java serialization is involved.
 * <p>
 * Format: {@code base64url(username) "." base64url(HMAC-SHA256(key, username))}.
 * Verification fails closed: an unset/short key, malformed value or MAC mismatch yields {@code null}.
 */
public final class RememberMeToken {

    private static final String HMAC = "HmacSHA256";
    private static final int MIN_KEY_BYTES = 16;
    private static final int MAX_TOKEN_CHARS = 1024;
    private static final int MAX_USERNAME_BYTES = 256;

    private RememberMeToken() {
    }

    /**
     * Returns the verified username, or {@code null} if the token is not valid.
     */
    public static String verify(String token, String key) {
        if (token == null || token.length() > MAX_TOKEN_CHARS || !keyUsable(key)) {
            return null;
        }
        int dot = token.indexOf('.');
        if (dot <= 0 || dot != token.lastIndexOf('.') || dot == token.length() - 1) {
            return null;
        }
        try {
            byte[] user = Base64.getUrlDecoder().decode(token.substring(0, dot));
            byte[] mac = Base64.getUrlDecoder().decode(token.substring(dot + 1));
            if (user.length == 0 || user.length > MAX_USERNAME_BYTES) {
                return null;
            }
            if (!MessageDigest.isEqual(mac, hmac(user, key))) {
                return null;
            }
            return new String(user, StandardCharsets.UTF_8);
        } catch (IllegalArgumentException | GeneralSecurityException e) {
            return null;
        }
    }

    /**
     * Builds a signed token for the given username; throws if the key is unusable.
     */
    public static String issue(String username, String key) throws GeneralSecurityException {
        if (!keyUsable(key) || username == null || username.isEmpty()) {
            throw new IllegalArgumentException("remember-me key or username not usable");
        }
        byte[] user = username.getBytes(StandardCharsets.UTF_8);
        Base64.Encoder enc = Base64.getUrlEncoder().withoutPadding();
        return enc.encodeToString(user) + "." + enc.encodeToString(hmac(user, key));
    }

    private static boolean keyUsable(String key) {
        return key != null && key.getBytes(StandardCharsets.UTF_8).length >= MIN_KEY_BYTES;
    }

    private static byte[] hmac(byte[] data, String key) throws GeneralSecurityException {
        Mac mac = Mac.getInstance(HMAC);
        mac.init(new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), HMAC));
        return mac.doFinal(data);
    }
}
