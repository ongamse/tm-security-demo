package org.joychou.controller;

import org.junit.Test;

import javax.servlet.http.Cookie;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.junit.Assert.assertEquals;

public class DeserializeTest {

    private static String b64(byte[] b) {
        return Base64.getEncoder().encodeToString(b);
    }

    @Test
    public void parsesValidJsonIntoFixedDto() throws IOException {
        String v = b64("{\"name\":\"joychou\"}".getBytes(StandardCharsets.UTF_8));
        assertEquals("joychou", Deserialize.parseRememberMe(v).getName());
    }

    @Test(expected = IOException.class)
    public void rejectsUnknownFieldsAndTypeHints() throws IOException {
        String v = b64("{\"@class\":\"java.lang.Object\",\"name\":\"x\"}".getBytes(StandardCharsets.UTF_8));
        Deserialize.parseRememberMe(v);
    }

    @Test(expected = IOException.class)
    public void rejectsJavaSerializedBytes() throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(bos);
        oos.writeObject(new Dummy());
        oos.close();
        Deserialize.parseRememberMe(b64(bos.toByteArray()));
    }

    @Test(expected = IllegalArgumentException.class)
    public void rejectsInvalidBase64() throws IOException {
        Deserialize.parseRememberMe("!!!not-base64!!!");
    }

    @Test
    public void endpointsRejectMalformedCookie() {
        org.springframework.mock.web.MockHttpServletRequest req =
                new org.springframework.mock.web.MockHttpServletRequest();
        req.setCookies(new Cookie("rememberMe", b64("junk".getBytes(StandardCharsets.UTF_8))));
        Deserialize d = new Deserialize();
        assertEquals("Invalid rememberMe cookie.", d.rememberMeVul(req));
        assertEquals("Invalid rememberMe cookie.", d.rememberMeBlackClassCheck(req));
    }

    @Test
    public void endpointsAcceptValidCookie() {
        org.springframework.mock.web.MockHttpServletRequest req =
                new org.springframework.mock.web.MockHttpServletRequest();
        req.setCookies(new Cookie("rememberMe", b64("{\"name\":\"a\"}".getBytes(StandardCharsets.UTF_8))));
        Deserialize d = new Deserialize();
        assertEquals("Are u ok?", d.rememberMeVul(req));
        assertEquals("I'm very OK.", d.rememberMeBlackClassCheck(req));
    }

    static class Dummy implements Serializable {
        String name = "x";
    }
}
