package org.joychou.controller;

import com.thoughtworks.xstream.XStream;
import com.thoughtworks.xstream.io.xml.DomDriver;
import org.joychou.dao.User;
import org.joychou.util.WebUtils;
import org.joychou.util.XmlSecurity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.xml.sax.InputSource;

import javax.servlet.http.HttpServletRequest;
import javax.xml.parsers.DocumentBuilder;
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
        // Reject DOCTYPE/ENTITY and re-serialize through a hardened StAX reader before parsing.
        String safeXml = XmlSecurity.sanitize(xml);
        // Data-only binding into a fixed bean: no class names from the request are ever resolved
        // or instantiated (no XStream/native deserialization of attacker input).
        bindUser(safeXml);
        return "xstream";
    }

    /**
     * Binds the XStream-style document {@code <org.joychou.dao.User>...</org.joychou.dao.User>} onto a
     * {@link User} by reading only the known leaf elements as plain text.
     */
    private static User bindUser(String safeXml) throws Exception {
        DocumentBuilder builder = XmlSecurity.newDocumentBuilderFactory().newDocumentBuilder();
        Element root = builder.parse(new InputSource(new StringReader(safeXml))).getDocumentElement();
        if (!USER_ROOT.equals(root.getTagName())) {
            throw new IllegalArgumentException("Unexpected root element");
        }
        User user = new User();
        for (Node n = root.getFirstChild(); n != null; n = n.getNextSibling()) {
            if (n.getNodeType() != Node.ELEMENT_NODE) {
                continue;
            }
            String value = n.getTextContent();
            switch (n.getNodeName()) {
                case "id":
                    user.setId(Integer.valueOf(value.trim()));
                    break;
                case "username":
                    user.setUsername(value);
                    break;
                case "password":
                    user.setPassword(value);
                    break;
                default:
                    throw new IllegalArgumentException("Unexpected element");
            }
        }
        return user;
    }

    private static final String USER_ROOT = "org.joychou.dao.User";

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
