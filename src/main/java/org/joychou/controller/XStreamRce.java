package org.joychou.controller;

import com.thoughtworks.xstream.XStream;
import com.thoughtworks.xstream.io.xml.DomDriver;
import com.thoughtworks.xstream.security.NoTypePermission;
import com.thoughtworks.xstream.security.NullPermission;
import com.thoughtworks.xstream.security.PrimitiveTypePermission;
import org.joychou.dao.User;
import org.joychou.util.WebUtils;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import org.xml.sax.InputSource;

import javax.servlet.http.HttpServletRequest;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.StringReader;


@RestController
public class XStreamRce {

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
        rejectDoctype(xml);
        XStream xstream = secureXStream();
        xstream.fromXML(xml);
        return "xstream";
    }

    /**
     * XStream with a type allowlist: everything is denied except primitives and the listed classes.
     */
    private static XStream secureXStream() {
        XStream xstream = new XStream(new DomDriver());
        xstream.addPermission(NoTypePermission.NONE);
        xstream.addPermission(NullPermission.NULL);
        xstream.addPermission(PrimitiveTypePermission.PRIMITIVES);
        xstream.allowTypes(new Class[]{User.class, String.class, Integer.class});
        return xstream;
    }

    /**
     * Reject any XML carrying a DOCTYPE (XXE / entity expansion) before it reaches the XStream DOM driver.
     */
    private static void rejectDoctype(String xml) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
        dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        dbf.newDocumentBuilder().parse(new InputSource(new StringReader(xml)));
    }

    public static void main(String[] args) {
        User user = new User();
        user.setId(0);
        user.setUsername("admin");

        XStream xstream = secureXStream();
        String xml = xstream.toXML(user); // Serialize
        System.out.println(xml);

        user = (User) xstream.fromXML(xml); // Deserialize
        System.out.println(user.getId() + ": " + user.getUsername());
    }
}
