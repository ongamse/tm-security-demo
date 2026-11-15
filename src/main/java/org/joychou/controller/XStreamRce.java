package org.joychou.controller;

import com.thoughtworks.xstream.XStream;
import com.thoughtworks.xstream.io.xml.DomDriver;
import org.joychou.dao.User;
import org.joychou.util.WebUtils;
import org.joychou.util.XmlUtils;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;
import org.xml.sax.Attributes;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.helpers.DefaultHandler;

import javax.servlet.http.HttpServletRequest;
import java.io.StringReader;


@RestController
public class XStreamRce {

    private static final String USER_ROOT = "org.joychou.dao.User";

    /**
     * Fix method: untrusted XML is never handed to XStream.fromXML; it is parsed by a hardened SAX parser
     * into a plain {@link User} DTO (fixed element set, no type resolution, no DOCTYPE/entities).
     * Set Content-Type: application/xml
     *
     * @author JoyChou @2019-07-26
     */
    @PostMapping("/xstream")
    public String parseXml(HttpServletRequest request) throws Exception {
        // Reject DOCTYPE / external entities before parsing.
        String xml = XmlUtils.sanitizeXml(WebUtils.getRequestBody(request));
        parseUser(xml);
        return "xstream";
    }

    /**
     * Parse XML of the form {@code <org.joychou.dao.User><id>1</id><username>x</username></org.joychou.dao.User>}
     * into a User. Any other root or child element is rejected.
     */
    static User parseUser(String xml) throws Exception {
        final User user = new User();
        XmlUtils.newSecureSaxParser().parse(new InputSource(new StringReader(xml)), new DefaultHandler() {
            private int depth = 0;
            private String field;
            private final StringBuilder text = new StringBuilder();

            @Override
            public void startElement(String uri, String localName, String qName, Attributes attrs)
                    throws SAXException {
                depth++;
                if (depth == 1) {
                    if (!USER_ROOT.equals(qName)) {
                        throw new SAXException("Unsupported root element");
                    }
                } else if (depth == 2) {
                    if (!("id".equals(qName) || "username".equals(qName) || "password".equals(qName))) {
                        throw new SAXException("Unsupported element");
                    }
                    field = qName;
                    text.setLength(0);
                } else {
                    throw new SAXException("Unsupported nesting");
                }
            }

            @Override
            public void characters(char[] ch, int start, int length) {
                if (depth == 2) {
                    text.append(ch, start, length);
                }
            }

            @Override
            public void endElement(String uri, String localName, String qName) throws SAXException {
                if (depth == 2) {
                    String value = text.toString();
                    switch (field) {
                        case "id":
                            try {
                                user.setId(Integer.valueOf(value.trim()));
                            } catch (NumberFormatException e) {
                                throw new SAXException("Invalid id");
                            }
                            break;
                        case "username":
                            user.setUsername(value);
                            break;
                        default:
                            user.setPassword(value);
                            break;
                    }
                    field = null;
                }
                depth--;
            }
        });
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
