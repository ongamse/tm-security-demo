package org.joychou.security;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Base64;

/**
 * rememberMe cookie format: {@code base64(serialized) + "." + base64(HMAC-SHA256(serialized))}.
 * The HMAC is verified (constant time) with a server-side secret BEFORE any deserializer touches the bytes,
 * and only authenticated bytes are deserialized, through the allowlist {@link AntObjectInputStream}.
 * The secret comes from env REMEMBER_ME_HMAC_KEY (or system property remember.me.hmac.key); if it is
 * not configured every cookie is rejected (fail closed).
 */
public final class RememberMeCodec {

    private static final String ENV_KEY = "REMEMBER_ME_HMAC_KEY";
    private static final String PROP_KEY = "remember.me.hmac.key";
    private static final String HMAC_ALGO = "HmacSHA256";

    private RememberMeCodec() {
    }

    private static byte[] secret() {
        String key = System.getenv(ENV_KEY);
        if (key == null || key.isEmpty()) {
            key = System.getProperty(PROP_KEY);
        }
        if (key == null || key.isEmpty()) {
            return null;
        }
        return key.getBytes(StandardCharsets.UTF_8);
    }

    private static byte[] hmac(byte[] key, byte[] data) throws GeneralSecurityException {
        Mac mac = Mac.getInstance(HMAC_ALGO);
        mac.init(new SecretKeySpec(key, HMAC_ALGO));
        return mac.doFinal(data);
    }

    /**
     * Build a signed cookie value for the given serialized bytes (used by trusted server code / tests).
     */
    public static String sign(byte[] serialized) throws GeneralSecurityException {
        byte[] key = secret();
        if (key == null) {
            throw new GeneralSecurityException("rememberMe HMAC key is not configured");
        }
        return Base64.getEncoder().encodeToString(serialized) + "."
                + Base64.getEncoder().encodeToString(hmac(key, serialized));
    }

    /**
     * Authenticate the cookie value and return the verified serialized bytes.
     *
     * @throws SecurityException if the key is missing, the format is bad or the MAC does not match
     */
    public static byte[] verify(String cookieValue) {
        byte[] key = secret();
        if (key == null) {
            throw new SecurityException("rememberMe HMAC key is not configured");
        }
        int dot = cookieValue == null ? -1 : cookieValue.indexOf('.');
        if (dot <= 0 || dot == cookieValue.length() - 1) {
            throw new SecurityException("Invalid rememberMe cookie");
        }
        try {
            byte[] payload = Base64.getDecoder().decode(cookieValue.substring(0, dot));
            byte[] mac = Base64.getDecoder().decode(cookieValue.substring(dot + 1));
            if (!MessageDigest.isEqual(hmac(key, payload), mac)) {
                throw new SecurityException("Invalid rememberMe signature");
            }
            return payload;
        } catch (IllegalArgumentException | GeneralSecurityException e) {
            throw new SecurityException("Invalid rememberMe cookie", e);
        }
    }

    /**
     * Verify the HMAC first, then deserialize the authenticated bytes with the class allowlist.
     */
    public static Object readVerified(String cookieValue) throws IOException, ClassNotFoundException {
        byte[] verified = verify(cookieValue);
        try (AntObjectInputStream in = new AntObjectInputStream(new ByteArrayInputStream(verified))) {
            return in.readObject();
        }
    }
}
