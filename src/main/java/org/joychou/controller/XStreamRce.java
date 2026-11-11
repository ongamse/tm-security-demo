package org.joychou.controller;

import com.thoughtworks.xstream.XStream;
import com.thoughtworks.xstream.io.HierarchicalStreamReader;
import com.thoughtworks.xstream.io.StreamException;
import com.thoughtworks.xstream.io.xml.DomDriver;
import com.thoughtworks.xstream.io.xml.DomReader;
import org.joychou.dao.User;
import org.joychou.util.WebUtils;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import org.w3c.dom.Document;
import org.xml.sax.InputSource;

import javax.servlet.http.HttpServletRequest;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.Reader;


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
        XStream xstream = new XStream(new SecureDomDriver());
        xstream.fromXML(xml);
        return "xstream";
    }

    /**
     * DomDriver that parses with DOCTYPE and external entities disabled (XXE protection).
     */
    private static class SecureDomDriver extends DomDriver {
        @Override
        public HierarchicalStreamReader createReader(Reader in) {
            try {
                DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
                dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
                dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
                dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
                dbf.setXIncludeAware(false);
                dbf.setExpandEntityReferences(false);
                Document document = dbf.newDocumentBuilder().parse(new InputSource(in));
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
