package org.joychou.controller;

import com.thoughtworks.xstream.XStream;
import com.thoughtworks.xstream.io.xml.DomDriver;
import com.thoughtworks.xstream.io.xml.XppDriver;
import com.thoughtworks.xstream.security.NoTypePermission;
import com.thoughtworks.xstream.security.NullPermission;
import com.thoughtworks.xstream.security.PrimitiveTypePermission;
import org.joychou.dao.User;
import org.joychou.security.XmlSecurity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;


@RestController
public class XStreamRce {

    private static final int MAX_BODY_LENGTH = 65536;

    /**
     * Fix method: update xstream to 1.4.11
     * Xstream affected version: 1.4.10 or <= 1.4.6
     * Set Content-Type: application/xml
     *
     * @author JoyChou @2019-07-26
     */
    @PostMapping("/xstream")
    public String parseXml(HttpServletRequest request) throws Exception {
        if (request.getContentLength() > MAX_BODY_LENGTH) {
            return "Request body too large";
        }
        String xml;
        try {
            xml = XmlSecurity.readBody(request);
        } catch (java.io.IOException e) {
            return "Request body too large";
        }
        if (xml.length() > MAX_BODY_LENGTH) {
            return "Request body too large";
        }
        String canonical;
        try {
            // Reject DOCTYPE / external entities, then hand XStream only the canonical
            // document re-serialized from the hardened parse.
            canonical = XmlSecurity.canonicalize(xml);
        } catch (Exception e) {
            return "Invalid XML";
        }
        XStream xstream = new XStream(new XppDriver());
        // Security framework: deny everything by default, allow only the expected types.
        xstream.addPermission(NoTypePermission.NONE);
        xstream.addPermission(NullPermission.NULL);
        xstream.addPermission(PrimitiveTypePermission.PRIMITIVES);
        xstream.allowTypes(new Class[]{String.class, User.class});
        try {
            xstream.fromXML(canonical);
        } catch (RuntimeException e) {
            return "Invalid XML";
        }
        return "xstream";
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
