package org.joychou.controller;

import com.thoughtworks.xstream.XStream;
import com.thoughtworks.xstream.io.xml.DomDriver;
import org.joychou.dao.User;
import org.joychou.util.WebUtils;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

import javax.servlet.http.HttpServletRequest;
import javax.xml.parsers.DocumentBuilder;
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

        // Parse XML safely using a hardened DOM parser instead of XStream deserialization
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
        dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        dbf.setXIncludeAware(false);
        dbf.setExpandEntityReferences(false);
        DocumentBuilder db = dbf.newDocumentBuilder();
        Document doc = db.parse(new InputSource(new StringReader(xml)));

        Element root = doc.getDocumentElement();
        if (!"org.joychou.dao.User".equals(root.getTagName())
                && !"User".equals(root.getTagName())) {
            return "Invalid XML: only User objects are accepted";
        }

        User user = new User();
        NodeList idNodes = root.getElementsByTagName("id");
        if (idNodes.getLength() > 0) {
            String idText = idNodes.item(0).getTextContent().trim();
            if (!idText.isEmpty()) {
                user.setId(Integer.valueOf(idText));
            }
        }
        NodeList usernameNodes = root.getElementsByTagName("username");
        if (usernameNodes.getLength() > 0) {
            user.setUsername(usernameNodes.item(0).getTextContent());
        }
        NodeList passwordNodes = root.getElementsByTagName("password");
        if (passwordNodes.getLength() > 0) {
            user.setPassword(passwordNodes.item(0).getTextContent());
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
