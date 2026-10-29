package org.joychou.controller;

import org.joychou.security.LogSanitizer;
import org.springframework.web.util.HtmlUtils;
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

import java.io.*;

import org.xml.sax.InputSource;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.SAXParser;

import org.xml.sax.helpers.DefaultHandler;
import org.apache.commons.digester3.Digester;
import org.jdom2.input.SAXBuilder;
import org.joychou.security.SecureXml;
import org.joychou.util.WebUtils;
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

    @PostMapping("/xmlReader/vuln")
    public String xmlReaderVuln(HttpServletRequest request) {
        try {
            String body = SecureXml.requireNoDtd(WebUtils.getRequestBody(request));
            logger.info("Request body: {}", LogSanitizer.clean(body));
            XMLReader xmlReader = SecureXml.newXMLReader();
            xmlReader.parse(new InputSource(new StringReader(body)));  // parse xml
            return "xmlReader xxe vuln code";
        } catch (Exception e) {
            logger.error("Operation failed.", e);
            return EXCEPT;
        }
    }


    @RequestMapping(value = "/xmlReader/sec", method = RequestMethod.POST)
    public String xmlReaderSec(HttpServletRequest request) {
        try {
            String body = SecureXml.requireNoDtd(WebUtils.getRequestBody(request));
            logger.info("Request body: {}", LogSanitizer.clean(body));

            XMLReader xmlReader = SecureXml.newXMLReader();
            // fix code start
            //fix code end
            xmlReader.parse(new InputSource(new StringReader(body)));  // parse xml

        } catch (Exception e) {
            logger.error("Operation failed.", e);
            return EXCEPT;
        }

        return "xmlReader xxe security code";
    }


    @RequestMapping(value = "/SAXBuilder/vuln", method = RequestMethod.POST)
    public String SAXBuilderVuln(HttpServletRequest request) {
        try {
            String body = SecureXml.requireNoDtd(WebUtils.getRequestBody(request));
            logger.info("Request body: {}", LogSanitizer.clean(body));

            SAXBuilder builder = SecureXml.newSAXBuilder();
            // org.jdom2.Document document
            builder.build(new InputSource(new StringReader(body)));
            return "SAXBuilder xxe vuln code";
        } catch (Exception e) {
            logger.error("Operation failed.", e);
            return EXCEPT;
        }
    }

    @RequestMapping(value = "/SAXBuilder/sec", method = RequestMethod.POST)
    public String SAXBuilderSec(HttpServletRequest request) {
        try {
            String body = SecureXml.requireNoDtd(WebUtils.getRequestBody(request));
            logger.info("Request body: {}", LogSanitizer.clean(body));

            SAXBuilder builder = SecureXml.newSAXBuilder();
            // org.jdom2.Document document
            builder.build(new InputSource(new StringReader(body)));

        } catch (Exception e) {
            logger.error("Operation failed.", e);
            return EXCEPT;
        }

        return "SAXBuilder xxe security code";
    }

    @RequestMapping(value = "/SAXReader/vuln", method = RequestMethod.POST)
    public String SAXReaderVuln(HttpServletRequest request) {
        try {
            String body = SecureXml.requireNoDtd(WebUtils.getRequestBody(request));
            logger.info("Request body: {}", LogSanitizer.clean(body));

            SAXReader reader = SecureXml.newSAXReader();
            // org.dom4j.Document document
            reader.read(new InputSource(new StringReader(body))); // cause xxe

        } catch (Exception e) {
            logger.error("Operation failed.", e);
            return EXCEPT;
        }

        return "SAXReader xxe vuln code";
    }

    @RequestMapping(value = "/SAXReader/sec", method = RequestMethod.POST)
    public String SAXReaderSec(HttpServletRequest request) {
        try {
            String body = SecureXml.requireNoDtd(WebUtils.getRequestBody(request));
            logger.info("Request body: {}", LogSanitizer.clean(body));

            SAXReader reader = SecureXml.newSAXReader();
            // org.dom4j.Document document
            reader.read(new InputSource(new StringReader(body)));
        } catch (Exception e) {
            logger.error("Operation failed.", e);
            return EXCEPT;
        }
        return "SAXReader xxe security code";
    }

    @RequestMapping(value = "/SAXParser/vuln", method = RequestMethod.POST)
    public String SAXParserVuln(HttpServletRequest request) {
        try {
            String body = SecureXml.requireNoDtd(WebUtils.getRequestBody(request));
            logger.info("Request body: {}", LogSanitizer.clean(body));

            SAXParser parser = SecureXml.newSAXParser();
            parser.parse(new InputSource(new StringReader(body)), new DefaultHandler());  // parse xml

            return "SAXParser xxe vuln code";
        } catch (Exception e) {
            logger.error("Operation failed.", e);
            return EXCEPT;
        }
    }


    @RequestMapping(value = "/SAXParser/sec", method = RequestMethod.POST)
    public String SAXParserSec(HttpServletRequest request) {
        try {
            String body = SecureXml.requireNoDtd(WebUtils.getRequestBody(request));
            logger.info("Request body: {}", LogSanitizer.clean(body));

            SAXParser parser = SecureXml.newSAXParser();
            parser.parse(new InputSource(new StringReader(body)), new DefaultHandler());  // parse xml
        } catch (Exception e) {
            logger.error("Operation failed.", e);
            return EXCEPT;
        }
        return "SAXParser xxe security code";
    }


    @RequestMapping(value = "/Digester/vuln", method = RequestMethod.POST)
    public String DigesterVuln(HttpServletRequest request) {
        try {
            String body = SecureXml.requireNoDtd(WebUtils.getRequestBody(request));
            logger.info("Request body: {}", LogSanitizer.clean(body));

            Digester digester = SecureXml.newDigester();
            digester.parse(new StringReader(body));  // parse xml
        } catch (Exception e) {
            logger.error("Operation failed.", e);
            return EXCEPT;
        }
        return "Digester xxe vuln code";
    }

    @RequestMapping(value = "/Digester/sec", method = RequestMethod.POST)
    public String DigesterSec(HttpServletRequest request) {
        try {
            String body = SecureXml.requireNoDtd(WebUtils.getRequestBody(request));
            logger.info("Request body: {}", LogSanitizer.clean(body));

            Digester digester = SecureXml.newDigester();
            digester.parse(new StringReader(body));  // parse xml

            return "Digester xxe security code";
        } catch (Exception e) {
            logger.error("Operation failed.", e);
            return EXCEPT;
        }
    }


    /**
     * Use request.getInputStream to support UTF16 encoding.
     */
    @RequestMapping(value = "/DocumentBuilder/vuln", method = RequestMethod.POST)
    public String DocumentBuilderVuln(HttpServletRequest request) {
        try {
            DocumentBuilderFactory dbf = SecureXml.newDocumentBuilderFactory();
            DocumentBuilder db = dbf.newDocumentBuilder();
            byte[] raw = org.springframework.util.StreamUtils.copyToByteArray(request.getInputStream());
            // Check the decoded text for DTD/ENTITY declarations (UTF-8 and UTF-16) before parsing.
            SecureXml.requireNoDtd(new String(raw, java.nio.charset.StandardCharsets.UTF_8));
            SecureXml.requireNoDtd(new String(raw, java.nio.charset.StandardCharsets.UTF_16));
            SecureXml.requireNoDtd(new String(raw, java.nio.charset.StandardCharsets.UTF_16LE));
            InputSource is = new InputSource(new ByteArrayInputStream(raw));
            Document document = db.parse(is);  // parse xml

            // 遍历xml节点name和value
            StringBuilder buf = new StringBuilder();
            NodeList rootNodeList = document.getChildNodes();
            for (int i = 0; i < rootNodeList.getLength(); i++) {
                Node rootNode = rootNodeList.item(i);
                NodeList child = rootNode.getChildNodes();
                for (int j = 0; j < child.getLength(); j++) {
                    Node node = child.item(j);
                    buf.append(String.format("%s: %s\n", node.getNodeName(), node.getTextContent()));
                }
            }
            return HtmlUtils.htmlEscape(buf.toString());
        } catch (Exception e) {
            e.printStackTrace();
            logger.error("XML parsing failed.", e);
            return "Request failed.";
        }
    }

    @RequestMapping(value = "/DocumentBuilder/Sec", method = RequestMethod.POST)
    public String DocumentBuilderSec(HttpServletRequest request) {
        try {
            String body = SecureXml.requireNoDtd(WebUtils.getRequestBody(request));
            logger.info("Request body: {}", LogSanitizer.clean(body));

            DocumentBuilderFactory dbf = SecureXml.newDocumentBuilderFactory();
            DocumentBuilder db = dbf.newDocumentBuilder();
            StringReader sr = new StringReader(body);
            InputSource is = new InputSource(sr);
            db.parse(is);  // parse xml
            sr.close();
        } catch (Exception e) {
            logger.error("Operation failed.", e);
            return EXCEPT;
        }
        return "DocumentBuilder xxe security code";
    }


    @RequestMapping(value = "/DocumentBuilder/xinclude/vuln", method = RequestMethod.POST)
    public String DocumentBuilderXincludeVuln(HttpServletRequest request) {
        try {
            String body = SecureXml.requireNoDtd(WebUtils.getRequestBody(request));
            logger.info("Request body: {}", LogSanitizer.clean(body));

            DocumentBuilderFactory dbf = SecureXml.newDocumentBuilderFactory();
            dbf.setNamespaceAware(true);
            DocumentBuilder db = dbf.newDocumentBuilder();
            StringReader sr = new StringReader(body);
            InputSource is = new InputSource(sr);
            Document document = db.parse(is);  // parse xml

            NodeList rootNodeList = document.getChildNodes();
            response(rootNodeList);

            sr.close();
            return "DocumentBuilder xinclude xxe vuln code";
        } catch (Exception e) {
            logger.error("Operation failed.", e);
            return EXCEPT;
        }
    }


    @RequestMapping(value = "/DocumentBuilder/xinclude/sec", method = RequestMethod.POST)
    public String DocumentBuilderXincludeSec(HttpServletRequest request) {
        try {
            String body = SecureXml.requireNoDtd(WebUtils.getRequestBody(request));
            logger.info("Request body: {}", LogSanitizer.clean(body));
            DocumentBuilderFactory dbf = SecureXml.newDocumentBuilderFactory();

            dbf.setNamespaceAware(true);

            DocumentBuilder db = dbf.newDocumentBuilder();
            StringReader sr = new StringReader(body);
            InputSource is = new InputSource(sr);
            Document document = db.parse(is);  // parse xml

            NodeList rootNodeList = document.getChildNodes();
            response(rootNodeList);

            sr.close();
        } catch (Exception e) {
            logger.error("Operation failed.", e);
            return EXCEPT;
        }
        return "DocumentBuilder xinclude xxe vuln code";
    }


    @PostMapping("/XMLReader/vuln")
    public String XMLReaderVuln(HttpServletRequest request) {
        try {
            String body = SecureXml.requireNoDtd(WebUtils.getRequestBody(request));
            logger.info("Request body: {}", LogSanitizer.clean(body));

            XMLReader xmlReader = SecureXml.newXMLReader();
            xmlReader.parse(new InputSource(new StringReader(body)));

        } catch (Exception e) {
            logger.error("Operation failed.", e);
            return EXCEPT;
        }

        return "XMLReader xxe vuln code";
    }


    @PostMapping("/XMLReader/sec")
    public String XMLReaderSec(HttpServletRequest request) {
        try {
            String body = SecureXml.requireNoDtd(WebUtils.getRequestBody(request));
            logger.info("Request body: {}", LogSanitizer.clean(body));

            XMLReader xmlReader = SecureXml.newXMLReader();
            xmlReader.parse(new InputSource(new StringReader(body)));

        } catch (Exception e) {
            logger.error("Operation failed.", e);
            return EXCEPT;
        }
        return "XMLReader xxe security code";
    }


    /**
     * 修复该漏洞只需升级dom4j到2.1.1及以上，该版本及以上禁用了ENTITY；
     * 不带ENTITY的PoC不能利用，所以禁用ENTITY即可完成修复。
     */
    @PostMapping("/DocumentHelper/vuln")
    public String DocumentHelper(HttpServletRequest req) {
        try {
            String body = SecureXml.requireNoDtd(WebUtils.getRequestBody(req));
            SecureXml.newSAXReader().read(new StringReader(body)); // parse xml
        } catch (Exception e) {
            logger.error("Operation failed.", e);
            return EXCEPT;
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
                logger.info("xxeNode: {}", LogSanitizer.clean(xxeNode.getNodeValue()));
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
                logger.info("User: {}", LogSanitizer.clean(user));
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