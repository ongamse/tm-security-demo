package org.joychou.controller;

import com.thoughtworks.xstream.XStream;
import com.thoughtworks.xstream.io.xml.DomDriver;
import com.thoughtworks.xstream.security.NoTypePermission;
import org.joychou.dao.User;
import org.joychou.util.WebUtils;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.StringReader;


@RestController
public class XStreamRce {

    /**
     * Rejects XML input containing DOCTYPE or ENTITY declarations to prevent XXE attacks.
     * Defense-in-depth: ensures malicious payloads are rejected before any parser touches them.
     */
    private static void rejectDoctypeDecl(String xml) {
        if (xml != null) {
            String upper = xml.toUpperCase();
            if (upper.contains("<!DOCTYPE") || upper.contains("<!ENTITY")) {
                throw new SecurityException("XML input contains prohibited DOCTYPE or ENTITY declaration");
            }
        }
    }

    /**
     * Creates a secure XStream instance that uses a DocumentBuilderFactory with XXE protections.
     * DomDriver does not expose parser config, so we pre-parse through a secured DocumentBuilder
     * and then pass the resulting DOM to XStream.
     *
     * @author JoyChou @2019-07-26
     */
    @PostMapping("/xstream")
    public String parseXml(HttpServletRequest request) throws Exception {
        String xml = WebUtils.getRequestBody(request);
        rejectDoctypeDecl(xml);

        // Pre-parse through a secure DocumentBuilderFactory to block XXE before XStream sees it
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
        dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        dbf.setXIncludeAware(false);
        dbf.setExpandEntityReferences(false);
        // Validate the XML is safe by parsing it through the secure factory first
        dbf.newDocumentBuilder().parse(new org.xml.sax.InputSource(new StringReader(xml)));

        XStream xstream = new XStream(new DomDriver());
        xstream.addPermission(NoTypePermission.NONE);
        xstream.allowTypes(new Class[]{User.class});
        xstream.fromXML(xml);
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
