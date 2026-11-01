package org.joychou.controller;

import org.joychou.dao.User;
import org.joychou.security.XmlSafe;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import javax.servlet.http.HttpServletRequest;


@RestController
public class XStreamRce {

    private static final int MAX_FIELD_CHARS = 256;

    /**
     * The request XML is never handed to a object-graph deserializer (XStream). It is size-capped,
     * DOCTYPE/ENTITY-rejected, parsed with the hardened DOM parser, and only the allowed
     * plain-text fields of {@link User} are copied over manually.
     * Set Content-Type: application/xml
     *
     * @author JoyChou @2019-07-26
     */
    @PostMapping("/xstream")
    public String parseXml(HttpServletRequest request) throws Exception {
        byte[] xml = XmlSafe.readValidated(request.getInputStream());
        org.w3c.dom.Document document = XmlSafe.parseDocument(xml);
        User user = toUser(document.getDocumentElement());
        return "xstream";
    }

    /**
     * Map the allowed child elements (id, username) of the root element to a User. Unknown elements,
     * attributes (e.g. class=) and nested structures are ignored.
     */
    static User toUser(Element root) {
        User user = new User();
        for (Node n = root.getFirstChild(); n != null; n = n.getNextSibling()) {
            if (n.getNodeType() != Node.ELEMENT_NODE) {
                continue;
            }
            String name = n.getLocalName() != null ? n.getLocalName() : n.getNodeName();
            String text = n.getTextContent();
            if (text == null || text.length() > MAX_FIELD_CHARS) {
                throw new XmlSafe.RejectedXmlException();
            }
            text = text.trim();
            if ("id".equals(name)) {
                try {
                    user.setId(Integer.valueOf(text));
                } catch (NumberFormatException e) {
                    throw new XmlSafe.RejectedXmlException();
                }
            } else if ("username".equals(name)) {
                user.setUsername(text);
            }
        }
        return user;
    }

    public static void main(String[] args) {
        User user = new User();
        user.setId(0);
        user.setUsername("admin");
        System.out.println(user.getId() + ": " + user.getUsername());
    }
}
