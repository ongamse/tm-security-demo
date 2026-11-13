package org.joychou.controller;

import com.thoughtworks.xstream.XStream;
import com.thoughtworks.xstream.io.HierarchicalStreamReader;
import com.thoughtworks.xstream.io.StreamException;
import com.thoughtworks.xstream.io.xml.DomDriver;
import com.thoughtworks.xstream.io.xml.DomReader;
import com.thoughtworks.xstream.security.NoTypePermission;
import com.thoughtworks.xstream.security.NullPermission;
import com.thoughtworks.xstream.security.PrimitiveTypePermission;
import org.joychou.dao.User;
import org.joychou.security.SignedPayload;
import org.joychou.util.WebUtils;
import org.joychou.util.XmlSecurity;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;
import org.w3c.dom.Document;
import org.xml.sax.InputSource;

import javax.servlet.http.HttpServletRequest;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.InputStream;
import java.io.Reader;
import java.nio.charset.StandardCharsets;


@RestController
public class XStreamRce {

    // Empty by default: with no key configured every request is rejected (fail closed).
    @Value("${joychou.security.serial.hmac.key:}")
    private String hmacKey;

    /**
     * Fix method: update xstream to 1.4.11
     * Xstream affected version: 1.4.10 or <= 1.4.6
     * Set Content-Type: application/xml
     *
     * @author JoyChou @2019-07-26
     */
    @PostMapping("/xstream")
    public String parseXml(HttpServletRequest request) throws Exception {
        String xml = WebUtils.getRequestBody(request);
        // Authenticate the body (HMAC-SHA256 in X-Signature header) before it reaches XStream; fail closed.
        if (!SignedPayload.verify(xml.getBytes(StandardCharsets.UTF_8),
                request.getHeader("X-Signature"), hmacKey)) {
            return "Invalid signature.";
        }
        XStream xstream = new XStream(new SecureDomDriver());
        // Deny by default; only the expected types may be unmarshalled.
        xstream.addPermission(NoTypePermission.NONE);
        xstream.addPermission(NullPermission.NULL);
        xstream.addPermission(PrimitiveTypePermission.PRIMITIVES);
        xstream.allowTypes(new Class[]{User.class, String.class, Integer.class});
        xstream.fromXML(xml);
        return "xstream";
    }

    /**
     * DomDriver that parses with DOCTYPE and external entities disabled (XXE).
     */
    private static class SecureDomDriver extends DomDriver {
        @Override
        public HierarchicalStreamReader createReader(Reader in) {
            return createSecureReader(new InputSource(in));
        }

        @Override
        public HierarchicalStreamReader createReader(InputStream in) {
            return createSecureReader(new InputSource(in));
        }

        private HierarchicalStreamReader createSecureReader(InputSource source) {
            try {
                DocumentBuilderFactory dbf = XmlSecurity.newDocumentBuilderFactory();
                Document document = dbf.newDocumentBuilder().parse(source);
                return new DomReader(document, getNameCoder());
            } catch (Exception e) {
                throw new StreamException(e);
            }
        }
    }

    public static void main(String[] args) {
        User user = new User();
        user.setId(0);
        user.setUsername("admin");

        XStream xstream = new XStream(new DomDriver());
        String xml = xstream.toXML(user); // Serialize
        System.out.println(xml);

        user = (User) xstream.fromXML(xml); // Deserialize
        System.out.println(user.getId() + ": " + user.getUsername());
    }
}
