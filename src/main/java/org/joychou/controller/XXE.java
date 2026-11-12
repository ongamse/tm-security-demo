package org.joychou.controller;

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
import org.xml.sax.SAXException;
import org.xml.sax.XMLReader;

import java.io.*;

import org.xml.sax.InputSource;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.parsers.SAXParserFactory;
import javax.xml.parsers.SAXParser;

import org.xml.sax.helpers.DefaultHandler;
import org.apache.commons.digester3.Digester;
import org.jdom2.input.DOMBuilder;
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
            String body = WebUtils.getRequestBody(request);
            logger.info(body);
            XMLReader xmlReader = createXmlReader();
            xmlReader.parse(new InputSource(new StringReader(body)));  // parse xml
            return "xmlReader xxe vuln code";
        } catch (Exception e) {
            logger.error(e.toString());
            return EXCEPT;
        }
    }


    @RequestMapping(value = "/xmlReader/sec", method = RequestMethod.POST)
    public String xmlReaderSec(HttpServletRequest request) {
        try {
            String body = WebUtils.getRequestBody(request);
            logger.info(body);

            XMLReader xmlReader = createXmlReader();
            xmlReader.parse(new InputSource(new StringReader(body)));  // parse xml

        } catch (Exception e) {
            logger.error(e.toString());
            return EXCEPT;
        }

        return "xmlReader xxe security code";
    }


    @RequestMapping(value = "/SAXBuilder/vuln", method = RequestMethod.POST)
    public String SAXBuilderVuln(HttpServletRequest request) {
        try {
            String body = WebUtils.getRequestBody(request);
            logger.info(body);

            // org.jdom2.Document document
            buildJdomDocument(body);
            return "SAXBuilder xxe vuln code";
        } catch (Exception e) {
            logger.error(e.toString());
            return EXCEPT;
        }
    }

    @RequestMapping(value = "/SAXBuilder/sec", method = RequestMethod.POST)
    public String SAXBuilderSec(HttpServletRequest request) {
        try {
            String body = WebUtils.getRequestBody(request);
            logger.info(body);

            // org.jdom2.Document document
            buildJdomDocument(body);

        } catch (Exception e) {
            logger.error(e.toString());
            return EXCEPT;
        }

        return "SAXBuilder xxe security code";
    }

    @RequestMapping(value = "/SAXReader/vuln", method = RequestMethod.POST)
    public String SAXReaderVuln(HttpServletRequest request) {
        try {
            String body = WebUtils.getRequestBody(request);
            logger.info(body);

            SAXReader reader = createSaxReader();
            // org.dom4j.Document document
            reader.read(new InputSource(new StringReader(body)));

        } catch (Exception e) {
            logger.error(e.toString());
            return EXCEPT;
        }

        return "SAXReader xxe vuln code";
    }

    @RequestMapping(value = "/SAXReader/sec", method = RequestMethod.POST)
    public String SAXReaderSec(HttpServletRequest request) {
        try {
            String body = WebUtils.getRequestBody(request);
            logger.info(body);

            SAXReader reader = createSaxReader();
            // org.dom4j.Document document
            reader.read(new InputSource(new StringReader(body)));
        } catch (Exception e) {
            logger.error(e.toString());
            return EXCEPT;
        }
        return "SAXReader xxe security code";
    }

    @RequestMapping(value = "/SAXParser/vuln", method = RequestMethod.POST)
    public String SAXParserVuln(HttpServletRequest request) {
        try {
            String body = WebUtils.getRequestBody(request);
            logger.info(body);

            SAXParser parser = createSaxParser();
            parser.parse(new InputSource(new StringReader(body)), new DefaultHandler());  // parse xml

            return "SAXParser xxe vuln code";
        } catch (Exception e) {
            logger.error(e.toString());
            return EXCEPT;
        }
    }


    @RequestMapping(value = "/SAXParser/sec", method = RequestMethod.POST)
    public String SAXParserSec(HttpServletRequest request) {
        try {
            String body = WebUtils.getRequestBody(request);
            logger.info(body);

            SAXParser parser = createSaxParser();
            parser.parse(new InputSource(new StringReader(body)), new DefaultHandler());  // parse xml
        } catch (Exception e) {
            logger.error(e.toString());
            return EXCEPT;
        }
        return "SAXParser xxe security code";
    }


    @RequestMapping(value = "/Digester/vuln", method = RequestMethod.POST)
    public String DigesterVuln(HttpServletRequest request) {
        try {
            String body = WebUtils.getRequestBody(request);
            logger.info(body);

            Digester digester = createDigester();
            parseWithDigester(digester, body);  // parse xml with the hardened SAXParser
        } catch (Exception e) {
            logger.error(e.toString());
            return EXCEPT;
        }
        return "Digester xxe vuln code";
    }

    @RequestMapping(value = "/Digester/sec", method = RequestMethod.POST)
    public String DigesterSec(HttpServletRequest request) {
        try {
            String body = WebUtils.getRequestBody(request);
            logger.info(body);

            Digester digester = createDigester();
            parseWithDigester(digester, body);  // parse xml with the hardened SAXParser

            return "Digester xxe security code";
        } catch (Exception e) {
            logger.error(e.toString());
            return EXCEPT;
        }
    }


    /**
     * Use request.getInputStream to support UTF16 encoding.
     */
    @RequestMapping(value = "/DocumentBuilder/vuln", method = RequestMethod.POST)
    public String DocumentBuilderVuln(HttpServletRequest request) {
        try {
            DocumentBuilder db = createDocumentBuilder(false);
            InputSource is = new InputSource(request.getInputStream());
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
            logger.error(e.toString());
            return HtmlUtils.htmlEscape(e.toString());
        }
    }

    @RequestMapping(value = "/DocumentBuilder/Sec", method = RequestMethod.POST)
    public String DocumentBuilderSec(HttpServletRequest request) {
        try {
            String body = WebUtils.getRequestBody(request);
            logger.info(body);

            DocumentBuilder db = createDocumentBuilder(false);
            StringReader sr = new StringReader(body);
            InputSource is = new InputSource(sr);
            db.parse(is);  // parse xml
            sr.close();
        } catch (Exception e) {
            logger.error(e.toString());
            return EXCEPT;
        }
        return "DocumentBuilder xxe security code";
    }


    @RequestMapping(value = "/DocumentBuilder/xinclude/vuln", method = RequestMethod.POST)
    public String DocumentBuilderXincludeVuln(HttpServletRequest request) {
        try {
            String body = WebUtils.getRequestBody(request);
            logger.info(body);

            DocumentBuilder db = createDocumentBuilder(true);  // XInclude stays disabled
            StringReader sr = new StringReader(body);
            InputSource is = new InputSource(sr);
            Document document = db.parse(is);  // parse xml

            NodeList rootNodeList = document.getChildNodes();
            response(rootNodeList);

            sr.close();
            return "DocumentBuilder xinclude xxe vuln code";
        } catch (Exception e) {
            logger.error(e.toString());
            return EXCEPT;
        }
    }


    @RequestMapping(value = "/DocumentBuilder/xinclude/sec", method = RequestMethod.POST)
    public String DocumentBuilderXincludeSec(HttpServletRequest request) {
        try {
            String body = WebUtils.getRequestBody(request);
            logger.info(body);
            DocumentBuilder db = createDocumentBuilder(true);  // XInclude stays disabled
            StringReader sr = new StringReader(body);
            InputSource is = new InputSource(sr);
            Document document = db.parse(is);  // parse xml

            NodeList rootNodeList = document.getChildNodes();
            response(rootNodeList);

            sr.close();
        } catch (Exception e) {
            logger.error(e.toString());
            return EXCEPT;
        }
        return "DocumentBuilder xinclude xxe vuln code";
    }


    @PostMapping("/XMLReader/vuln")
    public String XMLReaderVuln(HttpServletRequest request) {
        try {
            String body = WebUtils.getRequestBody(request);
            logger.info(body);

            XMLReader xmlReader = createXmlReader();
            xmlReader.parse(new InputSource(new StringReader(body)));

        } catch (Exception e) {
            logger.error(e.toString());
            return EXCEPT;
        }

        return "XMLReader xxe vuln code";
    }


    @PostMapping("/XMLReader/sec")
    public String XMLReaderSec(HttpServletRequest request) {
        try {
            String body = WebUtils.getRequestBody(request);
            logger.info(body);

            XMLReader xmlReader = createXmlReader();
            xmlReader.parse(new InputSource(new StringReader(body)));

        } catch (Exception e) {
            logger.error(e.toString());
            return EXCEPT;
        }
        return "XMLReader xxe security code";
    }


    /**
     * Uses the hardened dom4j SAXReader (DOCTYPE rejected) instead of DocumentHelper.parseText.
     */
    @PostMapping("/DocumentHelper/vuln")
    public String DocumentHelper(HttpServletRequest req) {
        try {
            String body = WebUtils.getRequestBody(req);
            createSaxReader().read(new StringReader(body)); // parse xml with the hardened reader
        } catch (Exception e) {
            logger.error(e.toString());
            return EXCEPT;
        }

        return "DocumentHelper xxe vuln code";
    }


    /**
     * Hardened SAXParserFactory: DOCTYPE rejected, no external entities / DTDs, no XInclude.
     * Every SAXParser / XMLReader in this class is obtained through this factory.
     */
    private static SAXParserFactory createSaxParserFactory() throws ParserConfigurationException, SAXException {
        SAXParserFactory spf = SAXParserFactory.newInstance();
        spf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        spf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        spf.setFeature("http://xml.org/sax/features/external-general-entities", false);
        spf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        spf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
        spf.setXIncludeAware(false);
        spf.setValidating(false);
        return spf;
    }

    private static SAXParser createSaxParser() throws ParserConfigurationException, SAXException {
        SAXParser parser = createSaxParserFactory().newSAXParser();
        parser.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        parser.setProperty(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
        return parser;
    }

    private static XMLReader createXmlReader() throws ParserConfigurationException, SAXException {
        return createSaxParser().getXMLReader();
    }

    /**
     * Hardened DocumentBuilder: DOCTYPE rejected, no external entities / DTDs / schemas, no XInclude.
     */
    private static DocumentBuilder createDocumentBuilder(boolean namespaceAware) throws ParserConfigurationException {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
        dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        dbf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
        dbf.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        dbf.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
        dbf.setXIncludeAware(false);
        dbf.setExpandEntityReferences(false);
        dbf.setNamespaceAware(namespaceAware);
        return dbf.newDocumentBuilder();
    }

    /**
     * Parses the XML with the hardened JDK DocumentBuilder (DOCTYPE rejected, no external entities)
     * and converts the resulting DOM to a JDOM2 document.
     */
    private static org.jdom2.Document buildJdomDocument(String xml)
            throws ParserConfigurationException, SAXException, IOException {
        Document w3cDocument = createDocumentBuilder(true).parse(new InputSource(new StringReader(xml)));
        return new DOMBuilder().build(w3cDocument);
    }

    /**
     * Feeds the Digester as the SAX handler of the hardened SAXParser, so the Digester
     * never creates its own (unhardened) XML parser.
     */
    private static void parseWithDigester(Digester digester, String xml)
            throws ParserConfigurationException, SAXException, IOException {
        createSaxParser().parse(new InputSource(new StringReader(xml)), digester);
    }

    /**
     * Hardened dom4j SAXReader.
     */
    private static SAXReader createSaxReader() throws SAXException {
        SAXReader reader = new SAXReader();
        reader.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        reader.setFeature("http://xml.org/sax/features/external-general-entities", false);
        reader.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        reader.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
        reader.setIncludeExternalDTDDeclarations(false);
        reader.setIncludeInternalDTDDeclarations(false);
        return reader;
    }

    /**
     * Hardened commons-digester3 Digester.
     */
    private static Digester createDigester() throws ParserConfigurationException, SAXException {
        Digester digester = new Digester();
        digester.getFactory().setXIncludeAware(false);
        digester.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        digester.setFeature("http://xml.org/sax/features/external-general-entities", false);
        digester.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        digester.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
        return digester;
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