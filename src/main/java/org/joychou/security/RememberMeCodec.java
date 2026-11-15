package org.joychou.security;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * rememberMe cookie format: {@code base64(payload) + "." + base64(HMAC-SHA256(payload))} where payload is the
 * UTF-8 text {@code username:expiryEpochSeconds}.
 * The HMAC is verified (constant time) with a server-side secret BEFORE the payload is parsed, and the
 * payload is parsed as plain text with a strict regex. Java native deserialization is never used.
 * The secret comes from env REMEMBER_ME_HMAC_KEY (or system property remember.me.hmac.key); if it is
 * not configured every cookie is rejected (fail closed).
 */
public final class RememberMeCodec {

    private static final String ENV_KEY = "REMEMBER_ME_HMAC_KEY";
    private static final String PROP_KEY = "remember.me.hmac.key";
    private static final String HMAC_ALGO = "HmacSHA256";
    private static final int MAX_PAYLOAD_BYTES = 256;
    private static final String USERNAME_REGEX = "[A-Za-z0-9_.@-]{1,64}";
    private static final Pattern USERNAME_PATTERN = Pattern.compile(USERNAME_REGEX);
    private static final Pattern PAYLOAD_PATTERN = Pattern.compile("(" + USERNAME_REGEX + "):([0-9]{1,12})");

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
     * Build a signed cookie value for the given username and expiry (epoch seconds).
     *
     * @throws IllegalArgumentException if the username does not match the strict allowed format
     */
    public static String sign(String username, long expiryEpochSeconds) throws GeneralSecurityException {
        if (username == null || !USERNAME_PATTERN.matcher(username).matches() || expiryEpochSeconds < 0) {
            throw new IllegalArgumentException("Invalid rememberMe username or expiry");
        }
        return sign((username + ":" + expiryEpochSeconds).getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Verify the HMAC, then parse the authenticated plain-text payload ({@code username:expiryEpochSeconds})
     * with a strict regex. No Java deserialization is involved.
     *
     * @return the verified username
     * @throws SecurityException if the key is missing, the MAC is wrong, the payload is malformed or expired
     */
    public static String readVerified(String cookieValue) {
        byte[] verified = verify(cookieValue);
        if (verified.length > MAX_PAYLOAD_BYTES) {
            throw new SecurityException("Invalid rememberMe payload");
        }
        Matcher m = PAYLOAD_PATTERN.matcher(new String(verified, StandardCharsets.UTF_8));
        if (!m.matches()) {
            throw new SecurityException("Invalid rememberMe payload");
        }
        long expiry;
        try {
            expiry = Long.parseLong(m.group(2));
        } catch (NumberFormatException e) {
            throw new SecurityException("Invalid rememberMe payload", e);
        }
        if (expiry < System.currentTimeMillis() / 1000L) {
            throw new SecurityException("Expired rememberMe cookie");
        }
        return m.group(1);
    }
}
