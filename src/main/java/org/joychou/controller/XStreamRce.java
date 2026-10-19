package org.joychou.controller;

import com.thoughtworks.xstream.XStream;
import com.thoughtworks.xstream.io.xml.StaxDriver;
import org.joychou.dao.User;
import org.joychou.util.WebUtils;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;


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
        // Use StaxDriver instead of DomDriver to prevent XXE (StAX disables external entities by default)
        XStream xstream = new XStream(new StaxDriver());
        // Set up XStream security: deny all by default, then allow only known safe types
        XStream.setupDefaultSecurity(xstream);
        xstream.allowTypes(new Class[]{User.class});
        xstream.fromXML(xml);
        return "xstream";
    }

    public static void main(String[] args) {
        User user = new User();
        user.setId(0);
        user.setUsername("admin");

        XStream xstream = new XStream(new StaxDriver());
        XStream.setupDefaultSecurity(xstream);
        xstream.allowTypes(new Class[]{User.class});
        String xml = xstream.toXML(user); // Serialize
        System.out.println(xml);

        user = (User) xstream.fromXML(xml); // Deserialize
        System.out.println(user.getId() + ": " + user.getUsername());
    }
}
