package org.joychou.controller;

import com.thoughtworks.xstream.XStream;
import com.thoughtworks.xstream.io.xml.DomDriver;
import org.joychou.dao.User;
import org.joychou.security.XmlSecurity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.xml.sax.InputSource;

import javax.servlet.http.HttpServletRequest;
import java.io.StringReader;
import java.util.regex.Pattern;


@RestController
public class XStreamRce {

    private static final int MAX_BODY_LENGTH = 65536;
    private static final Pattern ID_PATTERN = Pattern.compile("^-?[0-9]{1,9}$");
    private static final Pattern USERNAME_PATTERN = Pattern.compile("^[A-Za-z0-9_.-]{1,64}$");

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
            // Reject DOCTYPE / external entities, then map only the canonical document
            // re-serialized from the hardened parse.
            canonical = XmlSecurity.canonicalize(xml);
        } catch (Exception e) {
            return "Invalid XML";
        }
        try {
            User user = toUser(canonical);
            if (user == null) {
                return "Invalid XML";
            }
        } catch (Exception e) {
            return "Invalid XML";
        }
        return "xstream";
    }

    /**
     * Map the canonical XML to a User by hand: only the root element's direct children
     * "id" (integer) and "username" (validated string) are read. No reflective object
     * graph construction takes place.
     */
    private static User toUser(String canonical) throws Exception {
        Document doc = XmlSecurity.newDocumentBuilder()
                .parse(new InputSource(new StringReader(canonical)));
        Element root = doc.getDocumentElement();
        if (root == null) {
            return null;
        }
        String idText = null;
        String username = null;
        for (Node n = root.getFirstChild(); n != null; n = n.getNextSibling()) {
            if (n.getNodeType() != Node.ELEMENT_NODE) {
                continue;
            }
            String text = n.getTextContent();
            if ("id".equals(n.getNodeName())) {
                idText = text;
            } else if ("username".equals(n.getNodeName())) {
                username = text;
            }
        }
        if (idText == null || username == null
                || !ID_PATTERN.matcher(idText.trim()).matches()
                || !USERNAME_PATTERN.matcher(username).matches()) {
            return null;
        }
        User user = new User();
        user.setId(Integer.valueOf(idText.trim()));
        user.setUsername(username);
        return user;
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
