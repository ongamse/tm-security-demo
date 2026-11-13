package org.joychou.security;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Base64;

/**
 * HMAC-SHA256 integrity gate for payloads that are about to be deserialized.
 * Fails closed: when no key is configured nothing is ever accepted.
 * The key comes from the property joychou.security.serial.hmac.key (env JSC_SERIAL_HMAC_KEY).
 */
public final class SignedPayload {

    private static final String HMAC_ALGORITHM = "HmacSHA256";

    private SignedPayload() {
    }

    /**
     * Compute Base64(HMAC-SHA256(key, data)).
     */
    public static String sign(byte[] data, String key) throws GeneralSecurityException {
        if (key == null || key.isEmpty()) {
            throw new GeneralSecurityException("HMAC key is not configured");
        }
        Mac mac = Mac.getInstance(HMAC_ALGORITHM);
        mac.init(new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), HMAC_ALGORITHM));
        return Base64.getEncoder().encodeToString(mac.doFinal(data));
    }

    /**
     * True only when a key is configured and the Base64 signature matches (constant-time compare).
     */
    public static boolean verify(byte[] data, String signature, String key) {
        if (key == null || key.isEmpty() || data == null || signature == null) {
            return false;
        }
        try {
            byte[] expected = sign(data, key).getBytes(StandardCharsets.UTF_8);
            byte[] actual = signature.getBytes(StandardCharsets.UTF_8);
            return MessageDigest.isEqual(expected, actual);
        } catch (GeneralSecurityException e) {
            return false;
        }
    }

    /**
     * Parse "<base64 payload>.<base64 hmac>" and return the decoded payload only if the
     * signature is valid; otherwise return null. Nothing is deserialized here.
     */
    public static byte[] verifyAndDecode(String signedValue, String key) {
        if (signedValue == null) {
            return null;
        }
        int sep = signedValue.lastIndexOf('.');
        if (sep <= 0 || sep == signedValue.length() - 1) {
            return null;
        }
        try {
            byte[] data = Base64.getDecoder().decode(signedValue.substring(0, sep));
            return verify(data, signedValue.substring(sep + 1), key) ? data : null;
        } catch (IllegalArgumentException e) {
            return null;
        }
    }
}
