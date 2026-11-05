package org.joychou.controller;

import org.dom4j.DocumentHelper;
import org.dom4j.io.SAXReader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.web.ProjectedPayload;
import org.springframework.http.HttpEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.util.HtmlUtils;

import javax.servlet.http.HttpServletRequest;

import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;
import org.xml.sax.XMLReader;

import java.io.*;
import java.util.Locale;

import org.xml.sax.InputSource;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.parsers.SAXParserFactory;
import javax.xml.parsers.SAXParser;

import org.xml.sax.helpers.DefaultHandler;
import org.apache.commons.digester3.Digester;
import org.jdom2.input.SAXBuilder;
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
            String body = requireNoDtd(WebUtils.getRequestBody(request));
            logger.info("Received xml request body, length: {}", body.length());
            XMLReader xmlReader = secureXmlReader();
            xmlReader.parse(new InputSource(new StringReader(body)));  // parse xml
            return "xmlReader xxe vuln code";
        } catch (Exception e) {
            logger.error("xxe except: {}", e.getClass().getSimpleName());
            return EXCEPT;
        }
    }


    @RequestMapping(value = "/xmlReader/sec", method = RequestMethod.POST)
    public String xmlReaderSec(HttpServletRequest request) {
        try {
            String body = requireNoDtd(WebUtils.getRequestBody(request));
            logger.info("Received xml request body, length: {}", body.length());

            // fix code start
            XMLReader xmlReader = secureXmlReader();
            //fix code end
            xmlReader.parse(new InputSource(new StringReader(body)));  // parse xml

        } catch (Exception e) {
            logger.error("xxe except: {}", e.getClass().getSimpleName());
            return EXCEPT;
        }

        return "xmlReader xxe security code";
    }


    @RequestMapping(value = "/SAXBuilder/vuln", method = RequestMethod.POST)
    public String SAXBuilderVuln(HttpServletRequest request) {
        try {
            String body = requireNoDtd(WebUtils.getRequestBody(request));
            logger.info("Received xml request body, length: {}", body.length());

            SAXBuilder builder = secureSaxBuilder();
            // org.jdom2.Document document
            builder.build(new InputSource(new StringReader(body)));
            return "SAXBuilder xxe vuln code";
        } catch (Exception e) {
            logger.error("xxe except: {}", e.getClass().getSimpleName());
            return EXCEPT;
        }
    }

    @RequestMapping(value = "/SAXBuilder/sec", method = RequestMethod.POST)
    public String SAXBuilderSec(HttpServletRequest request) {
        try {
            String body = requireNoDtd(WebUtils.getRequestBody(request));
            logger.info("Received xml request body, length: {}", body.length());

            SAXBuilder builder = secureSaxBuilder();
            // org.jdom2.Document document
            builder.build(new InputSource(new StringReader(body)));

        } catch (Exception e) {
            logger.error("xxe except: {}", e.getClass().getSimpleName());
            return EXCEPT;
        }

        return "SAXBuilder xxe security code";
    }

    @RequestMapping(value = "/SAXReader/vuln", method = RequestMethod.POST)
    public String SAXReaderVuln(HttpServletRequest request) {
        try {
            String body = requireNoDtd(WebUtils.getRequestBody(request));
            logger.info("Received xml request body, length: {}", body.length());

            SAXReader reader = secureSaxReader();
            // org.dom4j.Document document
            reader.read(new InputSource(new StringReader(body))); // cause xxe

        } catch (Exception e) {
            logger.error("xxe except: {}", e.getClass().getSimpleName());
            return EXCEPT;
        }

        return "SAXReader xxe vuln code";
    }

    @RequestMapping(value = "/SAXReader/sec", method = RequestMethod.POST)
    public String SAXReaderSec(HttpServletRequest request) {
        try {
            String body = requireNoDtd(WebUtils.getRequestBody(request));
            logger.info("Received xml request body, length: {}", body.length());

            SAXReader reader = secureSaxReader();
            // org.dom4j.Document document
            reader.read(new InputSource(new StringReader(body)));
        } catch (Exception e) {
            logger.error("xxe except: {}", e.getClass().getSimpleName());
            return EXCEPT;
        }
        return "SAXReader xxe security code";
    }

    @RequestMapping(value = "/SAXParser/vuln", method = RequestMethod.POST)
    public String SAXParserVuln(HttpServletRequest request) {
        try {
            String body = requireNoDtd(WebUtils.getRequestBody(request));
            logger.info("Received xml request body, length: {}", body.length());

            SAXParser parser = secureSaxParser();
            parser.parse(new InputSource(new StringReader(body)), new DefaultHandler());  // parse xml

            return "SAXParser xxe vuln code";
        } catch (Exception e) {
            logger.error("xxe except: {}", e.getClass().getSimpleName());
            return EXCEPT;
        }
    }


    @RequestMapping(value = "/SAXParser/sec", method = RequestMethod.POST)
    public String SAXParserSec(HttpServletRequest request) {
        try {
            String body = requireNoDtd(WebUtils.getRequestBody(request));
            logger.info("Received xml request body, length: {}", body.length());

            SAXParser parser = secureSaxParser();
            parser.parse(new InputSource(new StringReader(body)), new DefaultHandler());  // parse xml
        } catch (Exception e) {
            logger.error("xxe except: {}", e.getClass().getSimpleName());
            return EXCEPT;
        }
        return "SAXParser xxe security code";
    }


    @RequestMapping(value = "/Digester/vuln", method = RequestMethod.POST)
    public String DigesterVuln(HttpServletRequest request) {
        try {
            String body = requireNoDtd(WebUtils.getRequestBody(request));
            logger.info("Received xml request body, length: {}", body.length());

            Digester digester = secureDigester();
            digester.parse(new StringReader(body));  // parse xml
        } catch (Exception e) {
            logger.error("xxe except: {}", e.getClass().getSimpleName());
            return EXCEPT;
        }
        return "Digester xxe vuln code";
    }

    @RequestMapping(value = "/Digester/sec", method = RequestMethod.POST)
    public String DigesterSec(HttpServletRequest request) {
        try {
            String body = requireNoDtd(WebUtils.getRequestBody(request));
            logger.info("Received xml request body, length: {}", body.length());

            Digester digester = secureDigester();
            digester.parse(new StringReader(body));  // parse xml

            return "Digester xxe security code";
        } catch (Exception e) {
            logger.error("xxe except: {}", e.getClass().getSimpleName());
            return EXCEPT;
        }
    }


    /**
     * Use request.getInputStream to support UTF16 encoding.
     */
    @RequestMapping(value = "/DocumentBuilder/vuln", method = RequestMethod.POST)
    public String DocumentBuilderVuln(HttpServletRequest request) {
        try {
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
            dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            dbf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
            dbf.setXIncludeAware(false);
            dbf.setExpandEntityReferences(false);
            DocumentBuilder db = dbf.newDocumentBuilder();
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
            logger.error("xxe except: {}", e.getClass().getSimpleName());
            return EXCEPT;
        }
    }

    @RequestMapping(value = "/DocumentBuilder/Sec", method = RequestMethod.POST)
    public String DocumentBuilderSec(HttpServletRequest request) {
        try {
            String body = requireNoDtd(WebUtils.getRequestBody(request));
            logger.info("Received xml request body, length: {}", body.length());

            DocumentBuilderFactory dbf = secureDocumentBuilderFactory();
            DocumentBuilder db = dbf.newDocumentBuilder();
            StringReader sr = new StringReader(body);
            InputSource is = new InputSource(sr);
            db.parse(is);  // parse xml
            sr.close();
        } catch (Exception e) {
            logger.error("xxe except: {}", e.getClass().getSimpleName());
            return EXCEPT;
        }
        return "DocumentBuilder xxe security code";
    }


    @RequestMapping(value = "/DocumentBuilder/xinclude/vuln", method = RequestMethod.POST)
    public String DocumentBuilderXincludeVuln(HttpServletRequest request) {
        try {
            String body = requireNoDtd(WebUtils.getRequestBody(request));
            logger.info("Received xml request body, length: {}", body.length());

            DocumentBuilderFactory dbf = secureDocumentBuilderFactory();
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
            logger.error("xxe except: {}", e.getClass().getSimpleName());
            return EXCEPT;
        }
    }


    @RequestMapping(value = "/DocumentBuilder/xinclude/sec", method = RequestMethod.POST)
    public String DocumentBuilderXincludeSec(HttpServletRequest request) {
        try {
            String body = requireNoDtd(WebUtils.getRequestBody(request));
            logger.info("Received xml request body, length: {}", body.length());
            DocumentBuilderFactory dbf = secureDocumentBuilderFactory();
            dbf.setNamespaceAware(true);

            DocumentBuilder db = dbf.newDocumentBuilder();
            StringReader sr = new StringReader(body);
            InputSource is = new InputSource(sr);
            Document document = db.parse(is);  // parse xml

            NodeList rootNodeList = document.getChildNodes();
            response(rootNodeList);

            sr.close();
        } catch (Exception e) {
            logger.error("xxe except: {}", e.getClass().getSimpleName());
            return EXCEPT;
        }
        return "DocumentBuilder xinclude xxe vuln code";
    }


    @PostMapping("/XMLReader/vuln")
    public String XMLReaderVuln(HttpServletRequest request) {
        try {
            String body = requireNoDtd(WebUtils.getRequestBody(request));
            logger.info("Received xml request body, length: {}", body.length());

            XMLReader xmlReader = secureXmlReader();
            xmlReader.parse(new InputSource(new StringReader(body)));

        } catch (Exception e) {
            logger.error("xxe except: {}", e.getClass().getSimpleName());
            return EXCEPT;
        }

        return "XMLReader xxe vuln code";
    }


    @PostMapping("/XMLReader/sec")
    public String XMLReaderSec(HttpServletRequest request) {
        try {
            String body = requireNoDtd(WebUtils.getRequestBody(request));
            logger.info("Received xml request body, length: {}", body.length());

            XMLReader xmlReader = secureXmlReader();
            xmlReader.parse(new InputSource(new StringReader(body)));

        } catch (Exception e) {
            logger.error("xxe except: {}", e.getClass().getSimpleName());
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
            String body = requireNoDtd(WebUtils.getRequestBody(req));
            DocumentHelper.parseText(body); // parse xml
        } catch (Exception e) {
            logger.error("xxe except: {}", e.getClass().getSimpleName());
            return EXCEPT;
        }

        return "DocumentHelper xxe vuln code";
    }


    /**
     * Single gate for every attacker-supplied XML string: NULs are stripped and any payload that
     * declares a DOCTYPE or ENTITY is rejected before it reaches a parser. The caller's existing
     * exception handler turns the IllegalArgumentException into the fixed error response.
     */
    private static String requireNoDtd(String xml) {
        if (xml == null) {
            throw new IllegalArgumentException("xml payload is required");
        }
        String cleaned = xml.replace("\0", "");
        String lower = cleaned.toLowerCase(Locale.ROOT);
        if (lower.contains("<!doctype") || lower.contains("<!entity")) {
            throw new IllegalArgumentException("DTD declarations are not allowed");
        }
        return cleaned;
    }

    private static final String FEATURE_DISALLOW_DOCTYPE = "http://apache.org/xml/features/disallow-doctype-decl";
    private static final String FEATURE_EXTERNAL_GENERAL = "http://xml.org/sax/features/external-general-entities";
    private static final String FEATURE_EXTERNAL_PARAMETER = "http://xml.org/sax/features/external-parameter-entities";
    private static final String FEATURE_LOAD_EXTERNAL_DTD = "http://apache.org/xml/features/nonvalidating/load-external-dtd";

    private static SAXParserFactory secureSaxParserFactory() throws ParserConfigurationException, SAXException {
        SAXParserFactory spf = SAXParserFactory.newInstance();
        spf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        spf.setFeature(FEATURE_DISALLOW_DOCTYPE, true);
        spf.setFeature(FEATURE_EXTERNAL_GENERAL, false);
        spf.setFeature(FEATURE_EXTERNAL_PARAMETER, false);
        spf.setFeature(FEATURE_LOAD_EXTERNAL_DTD, false);
        spf.setXIncludeAware(false);
        return spf;
    }

    private static SAXParser secureSaxParser() throws ParserConfigurationException, SAXException {
        SAXParser parser = secureSaxParserFactory().newSAXParser();
        try {
            parser.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, "");
            parser.setProperty(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
        } catch (SAXException e) {
            logger.debug("access external properties not supported: {}", e.getClass().getSimpleName());
        }
        return parser;
    }

    private static XMLReader secureXmlReader() throws ParserConfigurationException, SAXException {
        XMLReader xmlReader = secureSaxParser().getXMLReader();
        xmlReader.setFeature(FEATURE_DISALLOW_DOCTYPE, true);
        xmlReader.setFeature(FEATURE_EXTERNAL_GENERAL, false);
        xmlReader.setFeature(FEATURE_EXTERNAL_PARAMETER, false);
        xmlReader.setFeature(FEATURE_LOAD_EXTERNAL_DTD, false);
        return xmlReader;
    }

    private static SAXBuilder secureSaxBuilder() {
        SAXBuilder builder = new SAXBuilder();
        builder.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        builder.setFeature(FEATURE_DISALLOW_DOCTYPE, true);
        builder.setFeature(FEATURE_EXTERNAL_GENERAL, false);
        builder.setFeature(FEATURE_EXTERNAL_PARAMETER, false);
        builder.setFeature(FEATURE_LOAD_EXTERNAL_DTD, false);
        builder.setExpandEntities(false);
        return builder;
    }

    private static SAXReader secureSaxReader() throws SAXException {
        SAXReader reader = new SAXReader();
        reader.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        reader.setFeature(FEATURE_DISALLOW_DOCTYPE, true);
        reader.setFeature(FEATURE_EXTERNAL_GENERAL, false);
        reader.setFeature(FEATURE_EXTERNAL_PARAMETER, false);
        reader.setFeature(FEATURE_LOAD_EXTERNAL_DTD, false);
        try {
            reader.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, "");
            reader.setProperty(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
        } catch (SAXException e) {
            logger.debug("access external properties not supported: {}", e.getClass().getSimpleName());
        }
        return reader;
    }

    private static Digester secureDigester() throws ParserConfigurationException, SAXException {
        Digester digester = new Digester();
        digester.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        digester.setFeature(FEATURE_DISALLOW_DOCTYPE, true);
        digester.setFeature(FEATURE_EXTERNAL_GENERAL, false);
        digester.setFeature(FEATURE_EXTERNAL_PARAMETER, false);
        digester.setFeature(FEATURE_LOAD_EXTERNAL_DTD, false);
        return digester;
    }

    private static DocumentBuilderFactory secureDocumentBuilderFactory() throws ParserConfigurationException {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        dbf.setFeature(FEATURE_DISALLOW_DOCTYPE, true);
        dbf.setFeature(FEATURE_EXTERNAL_GENERAL, false);
        dbf.setFeature(FEATURE_EXTERNAL_PARAMETER, false);
        dbf.setFeature(FEATURE_LOAD_EXTERNAL_DTD, false);
        dbf.setXIncludeAware(false);
        dbf.setExpandEntityReferences(false);
        try {
            dbf.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
            dbf.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
            dbf.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "");
        } catch (IllegalArgumentException e) {
            logger.debug("access external attributes not supported: {}", e.getClass().getSimpleName());
        }
        return dbf;
    }

    private static void response(NodeList rootNodeList){
        for (int i = 0; i < rootNodeList.getLength(); i++) {
            Node rootNode = rootNodeList.item(i);
            NodeList xxe = rootNode.getChildNodes();
            for (int j = 0; j < xxe.getLength(); j++) {
                Node xxeNode = xxe.item(j);
                // 测试不能blind xxe，所以强行加了一个回显
                logger.info("xxeNode type: {}", xxeNode.getNodeType());
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
                logger.info("Received xmlbeam request.");
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