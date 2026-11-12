package org.joychou.controller;

import org.joychou.dao.User;
import org.joychou.util.WebUtils;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

import javax.servlet.http.HttpServletRequest;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.StringReader;
import java.util.HashSet;
import java.util.Set;
import java.util.regex.Pattern;


@RestController
public class XStreamRce {

    private static final int MAX_XML_CHARS = 16 * 1024;
    private static final int MAX_PASSWORD_CHARS = 128;
    private static final Pattern ID_PATTERN = Pattern.compile("^-?[0-9]{1,10}$");
    private static final Pattern USERNAME_PATTERN = Pattern.compile("^[A-Za-z0-9_.-]{1,64}$");

    /**
     * The request body is expected to be a User document, for example
     * &lt;org.joychou.dao.User&gt;&lt;id&gt;1&lt;/id&gt;&lt;username&gt;admin&lt;/username&gt;&lt;/org.joychou.dao.User&gt;.
     * It is bound by hand from a hardened DOM parse; no object deserialization framework is used,
     * so the payload can never choose which classes get instantiated.
     * Set Content-Type: application/xml
     *
     * @author JoyChou @2019-07-26
     */
    @PostMapping("/xstream")
    public String parseXml(HttpServletRequest request) throws Exception {
        String xml = WebUtils.getRequestBody(request);
        if (xml == null || xml.length() > MAX_XML_CHARS) {
            return "invalid xml";
        }
        try {
            DocumentBuilder builder = newSecureDocumentBuilderFactory().newDocumentBuilder();
            Document doc = builder.parse(new InputSource(new StringReader(xml)));
            if (bindUser(doc.getDocumentElement()) == null) {
                return "invalid xml";
            }
        } catch (Exception e) {
            return "invalid xml";
        }
        return "xstream";
    }

    private static DocumentBuilderFactory newSecureDocumentBuilderFactory() throws ParserConfigurationException {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
        dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        dbf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
        dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        dbf.setXIncludeAware(false);
        dbf.setExpandEntityReferences(false);
        return dbf;
    }

    /**
     * Builds a User from the root element, or returns null when the document does not have the
     * accepted shape (root org.joychou.dao.User or user; only id, username, password children,
     * each at most once and containing text only; no attributes).
     */
    private static User bindUser(Element root) {
        if (root == null) {
            return null;
        }
        String rootName = root.getTagName();
        if (!"org.joychou.dao.User".equals(rootName) && !"user".equals(rootName)) {
            return null;
        }
        if (root.hasAttributes()) {
            return null;
        }

        User user = new User();
        Set<String> seen = new HashSet<String>();
        NodeList children = root.getChildNodes();
        for (int i = 0; i < children.getLength(); i++) {
            Node node = children.item(i);
            short type = node.getNodeType();
            if (type == Node.COMMENT_NODE) {
                continue;
            }
            if (type == Node.TEXT_NODE) {
                if (node.getNodeValue().trim().isEmpty()) {
                    continue;
                }
                return null;
            }
            if (type != Node.ELEMENT_NODE) {
                return null;
            }
            Element child = (Element) node;
            String name = child.getTagName();
            String value = textOnly(child);
            if (value == null || !seen.add(name)) {
                return null;
            }
            if ("id".equals(name)) {
                String trimmed = value.trim();
                if (!ID_PATTERN.matcher(trimmed).matches()) {
                    return null;
                }
                try {
                    user.setId(Integer.valueOf(Integer.parseInt(trimmed)));
                } catch (NumberFormatException e) {
                    return null;
                }
            } else if ("username".equals(name)) {
                if (!USERNAME_PATTERN.matcher(value).matches()) {
                    return null;
                }
                user.setUsername(value);
            } else if ("password".equals(name)) {
                if (value.length() > MAX_PASSWORD_CHARS) {
                    return null;
                }
                user.setPassword(value);
            } else {
                return null;
            }
        }
        return user;
    }

    /** Returns the element's text, or null if it has attributes or any non-text child node. */
    private static String textOnly(Element element) {
        if (element.hasAttributes()) {
            return null;
        }
        StringBuilder sb = new StringBuilder();
        NodeList kids = element.getChildNodes();
        for (int i = 0; i < kids.getLength(); i++) {
            Node kid = kids.item(i);
            short type = kid.getNodeType();
            if (type == Node.TEXT_NODE || type == Node.CDATA_SECTION_NODE) {
                sb.append(kid.getNodeValue());
            } else if (type != Node.COMMENT_NODE) {
                return null;
            }
        }
        return sb.toString();
    }

    public static void main(String[] args) throws Exception {
        String xml = "<org.joychou.dao.User><id>0</id><username>admin</username></org.joychou.dao.User>";
        DocumentBuilder builder = newSecureDocumentBuilderFactory().newDocumentBuilder();
        User user = bindUser(builder.parse(new InputSource(new StringReader(xml))).getDocumentElement());
        System.out.println(user.getId() + ": " + user.getUsername());
    }
}
