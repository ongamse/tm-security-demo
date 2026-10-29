package org.joychou.controller;

import com.thoughtworks.xstream.XStream;
import com.thoughtworks.xstream.io.xml.DomDriver;
import org.joychou.dao.User;
import org.joychou.security.SecureXml;
import org.joychou.util.WebUtils;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;
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
        // Reject DOCTYPE / ENTITY declarations before the body reaches the parser.
        String xml = SecureXml.requireNoDtd(WebUtils.getRequestBody(request));
        if (xml == null || xml.isEmpty()) {
            return "xstream";
        }
        // Data-only parsing: read simple fields from a hardened DOM, never instantiate types from XML.
        DocumentBuilder builder = SecureXml.newDocumentBuilderFactory().newDocumentBuilder();
        Document doc = builder.parse(new InputSource(new StringReader(xml)));

        User user = new User();
        String id = textOf(doc, "id");
        if (id != null) {
            user.setId(Integer.valueOf(id.trim()));
        }
        user.setUsername(textOf(doc, "username"));
        user.setPassword(textOf(doc, "password"));
        return "xstream";
    }

    private static String textOf(Document doc, String tag) {
        NodeList nodes = doc.getElementsByTagName(tag);
        return nodes.getLength() == 0 ? null : nodes.item(0).getTextContent();
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
