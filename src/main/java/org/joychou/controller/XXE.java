package org.joychou.controller;

import org.dom4j.io.SAXReader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.web.ProjectedPayload;
import org.springframework.http.HttpEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;

import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.XMLReader;

import java.io.IOException;


import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.SAXParser;

import org.xml.sax.helpers.DefaultHandler;
import org.apache.commons.digester3.Digester;
import org.jdom2.input.SAXBuilder;
import org.joychou.security.XmlSafe;
import org.xmlbeam.annotation.XBRead;

/**
 * Java xxe vuln and security code.
 *
 * @author JoyChou @2017-12-22
 */

@RestController
@RequestMapping("/xxe")
public class XXE {

    private static final Logger logger = LoggerFactory.getLogger(XXE.class);
    private static final String EXCEPT = "xxe except";

    /**
     * Read the request body once, size-capped, and reject any DOCTYPE / ENTITY before a parser sees it.
     * Rejected payloads surface as HTTP 400 without echoing the input.
     */
    private static byte[] validatedBody(HttpServletRequest request) throws IOException {
        return XmlSafe.readValidated(request.getInputStream());
    }

    private static String fail(Exception e) {
        if (e instanceof XmlSafe.RejectedXmlException) {
            throw (XmlSafe.RejectedXmlException) e;
        }
        logger.error("xml parse failed: {}", e.getClass().getSimpleName());
        return EXCEPT;
    }

    @PostMapping("/xmlReader/vuln")
    public String xmlReaderVuln(HttpServletRequest request) {
        try {
            byte[] xml = validatedBody(request);
            XMLReader xmlReader = XmlSafe.newXMLReader();
            xmlReader.parse(XmlSafe.toInputSource(xml));  // parse xml
            return "xmlReader xxe vuln code";
        } catch (Exception e) {
            return fail(e);
        }
    }


    @RequestMapping(value = "/xmlReader/sec", method = RequestMethod.POST)
    public String xmlReaderSec(HttpServletRequest request) {
        try {
            byte[] xml = validatedBody(request);
            XMLReader xmlReader = XmlSafe.newXMLReader();
            xmlReader.parse(XmlSafe.toInputSource(xml));  // parse xml
        } catch (Exception e) {
            return fail(e);
        }

        return "xmlReader xxe security code";
    }


    @RequestMapping(value = "/SAXBuilder/vuln", method = RequestMethod.POST)
    public String SAXBuilderVuln(HttpServletRequest request) {
        try {
            byte[] xml = validatedBody(request);
            SAXBuilder builder = XmlSafe.newSAXBuilder();
            // org.jdom2.Document document
            builder.build(XmlSafe.toInputSource(xml));
            return "SAXBuilder xxe vuln code";
        } catch (Exception e) {
            return fail(e);
        }
    }

    @RequestMapping(value = "/SAXBuilder/sec", method = RequestMethod.POST)
    public String SAXBuilderSec(HttpServletRequest request) {
        try {
            byte[] xml = validatedBody(request);
            SAXBuilder builder = XmlSafe.newSAXBuilder();
            // org.jdom2.Document document
            builder.build(XmlSafe.toInputSource(xml));
        } catch (Exception e) {
            return fail(e);
        }

        return "SAXBuilder xxe security code";
    }

    @RequestMapping(value = "/SAXReader/vuln", method = RequestMethod.POST)
    public String SAXReaderVuln(HttpServletRequest request) {
        try {
            byte[] xml = validatedBody(request);
            SAXReader reader = XmlSafe.newSAXReader();
            // org.dom4j.Document document
            reader.read(XmlSafe.toInputSource(xml));
        } catch (Exception e) {
            return fail(e);
        }

        return "SAXReader xxe vuln code";
    }

    @RequestMapping(value = "/SAXReader/sec", method = RequestMethod.POST)
    public String SAXReaderSec(HttpServletRequest request) {
        try {
            byte[] xml = validatedBody(request);
            SAXReader reader = XmlSafe.newSAXReader();
            // org.dom4j.Document document
            reader.read(XmlSafe.toInputSource(xml));
        } catch (Exception e) {
            return fail(e);
        }
        return "SAXReader xxe security code";
    }

    @RequestMapping(value = "/SAXParser/vuln", method = RequestMethod.POST)
    public String SAXParserVuln(HttpServletRequest request) {
        try {
            byte[] xml = validatedBody(request);
            SAXParser parser = XmlSafe.newSAXParser();
            parser.parse(XmlSafe.toInputSource(xml), new DefaultHandler());  // parse xml

            return "SAXParser xxe vuln code";
        } catch (Exception e) {
            return fail(e);
        }
    }


    @RequestMapping(value = "/SAXParser/sec", method = RequestMethod.POST)
    public String SAXParserSec(HttpServletRequest request) {
        try {
            byte[] xml = validatedBody(request);
            SAXParser parser = XmlSafe.newSAXParser();
            parser.parse(XmlSafe.toInputSource(xml), new DefaultHandler());  // parse xml
        } catch (Exception e) {
            return fail(e);
        }
        return "SAXParser xxe security code";
    }


    @RequestMapping(value = "/Digester/vuln", method = RequestMethod.POST)
    public String DigesterVuln(HttpServletRequest request) {
        try {
            byte[] xml = validatedBody(request);
            Digester digester = XmlSafe.newDigester();
            digester.parse(XmlSafe.toInputSource(xml));  // parse xml
        } catch (Exception e) {
            return fail(e);
        }
        return "Digester xxe vuln code";
    }

    @RequestMapping(value = "/Digester/sec", method = RequestMethod.POST)
    public String DigesterSec(HttpServletRequest request) {
        try {
            byte[] xml = validatedBody(request);
            Digester digester = XmlSafe.newDigester();
            digester.parse(XmlSafe.toInputSource(xml));  // parse xml

            return "Digester xxe security code";
        } catch (Exception e) {
            return fail(e);
        }
    }


    /**
     * Use request.getInputStream to support UTF16 encoding.
     * The parsed content is no longer reflected to the caller.
     */
    @RequestMapping(value = "/DocumentBuilder/vuln", method = RequestMethod.POST)
    public String DocumentBuilderVuln(HttpServletRequest request) {
        try {
            byte[] xml = validatedBody(request);
            DocumentBuilder db = XmlSafe.newDocumentBuilder();
            db.parse(XmlSafe.toInputSource(xml));  // parse xml
            return "DocumentBuilder xxe vuln code";
        } catch (Exception e) {
            return fail(e);
        }
    }

    @RequestMapping(value = "/DocumentBuilder/Sec", method = RequestMethod.POST)
    public String DocumentBuilderSec(HttpServletRequest request) {
        try {
            byte[] xml = validatedBody(request);
            DocumentBuilder db = XmlSafe.newDocumentBuilder();
            db.parse(XmlSafe.toInputSource(xml));  // parse xml
        } catch (Exception e) {
            return fail(e);
        }
        return "DocumentBuilder xxe security code";
    }


    @RequestMapping(value = "/DocumentBuilder/xinclude/vuln", method = RequestMethod.POST)
    public String DocumentBuilderXincludeVuln(HttpServletRequest request) {
        try {
            byte[] xml = validatedBody(request);
            Document document = XmlSafe.parseDocument(xml);  // parse xml (XInclude disabled)

            NodeList rootNodeList = document.getChildNodes();
            response(rootNodeList);

            return "DocumentBuilder xinclude xxe vuln code";
        } catch (Exception e) {
            return fail(e);
        }
    }


    @RequestMapping(value = "/DocumentBuilder/xinclude/sec", method = RequestMethod.POST)
    public String DocumentBuilderXincludeSec(HttpServletRequest request) {
        try {
            byte[] xml = validatedBody(request);
            Document document = XmlSafe.parseDocument(xml);  // parse xml (XInclude disabled)

            NodeList rootNodeList = document.getChildNodes();
            response(rootNodeList);
        } catch (Exception e) {
            return fail(e);
        }
        return "DocumentBuilder xinclude xxe vuln code";
    }


    @PostMapping("/XMLReader/vuln")
    public String XMLReaderVuln(HttpServletRequest request) {
        try {
            byte[] xml = validatedBody(request);
            XMLReader xmlReader = XmlSafe.newXMLReader();
            xmlReader.parse(XmlSafe.toInputSource(xml));

        } catch (Exception e) {
            return fail(e);
        }

        return "XMLReader xxe vuln code";
    }


    @PostMapping("/XMLReader/sec")
    public String XMLReaderSec(HttpServletRequest request) {
        try {
            byte[] xml = validatedBody(request);
            XMLReader xmlReader = XmlSafe.newXMLReader();
            xmlReader.parse(XmlSafe.toInputSource(xml));

        } catch (Exception e) {
            return fail(e);
        }
        return "XMLReader xxe security code";
    }


    /**
     * DOCTYPE / ENTITY payloads are rejected before parsing and the reader is hardened.
     */
    @PostMapping("/DocumentHelper/vuln")
    public String DocumentHelper(HttpServletRequest req) {
        try {
            byte[] xml = validatedBody(req);
            XmlSafe.newSAXReader().read(XmlSafe.toInputSource(xml)); // parse xml
        } catch (Exception e) {
            return fail(e);
        }

        return "DocumentHelper xxe vuln code";
    }


    private static void response(NodeList rootNodeList){
        for (int i = 0; i < rootNodeList.getLength(); i++) {
            Node rootNode = rootNodeList.item(i);
            NodeList xxe = rootNode.getChildNodes();
            for (int j = 0; j < xxe.getLength(); j++) {
                Node xxeNode = xxe.item(j);
                // 测试不能blind xxe，所以强行加了一个回显
                logger.info("xxeNode: " + xxeNode.getNodeValue());
            }

        }
    }

        /**
         * Receiving POST requests supporting both JSON and XML.
         * CVE-2018-1259
         */
        @PostMapping(value = "/xmlbeam/vuln")
        HttpEntity<String> post(@RequestBody UserPayload user) {
            try {
                logger.info(user.toString());
                return ResponseEntity.ok(String.format("hello, %s!", user.getUserName()));
            }catch (Exception e){
                e.printStackTrace();
                return ResponseEntity.ok("error");
            }
        }

        /**
         * The projection interface using XPath and JSON Path expression to selectively pick elements from the payload.
         */
        @ProjectedPayload
        public interface UserPayload {
            @XBRead("//userName")
            String getUserName();
        }

    public static void main(String[] args) {

    }

}