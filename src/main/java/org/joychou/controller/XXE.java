package org.joychou.controller;

import org.dom4j.DocumentHelper;
import org.dom4j.io.SAXReader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.web.ProjectedPayload;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpStatus;
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
import java.util.regex.Matcher;
import java.util.regex.Pattern;

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
import org.joychou.security.SecurityUtil;
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
        String xml = rebuildXml(request);
        try {
            XMLReader xmlReader = secureXmlReader();
            xmlReader.parse(new InputSource(new StringReader(xml)));  // parse xml
            return "xmlReader xxe vuln code";
        } catch (Exception e) {
            logger.error("xxe except: {}", e.getClass().getSimpleName());
            return EXCEPT;
        }
    }


    @RequestMapping(value = "/xmlReader/sec", method = RequestMethod.POST)
    public String xmlReaderSec(HttpServletRequest request) {
        String xml = rebuildXml(request);
        try {
            // fix code start
            XMLReader xmlReader = secureXmlReader();
            //fix code end
            xmlReader.parse(new InputSource(new StringReader(xml)));  // parse xml

        } catch (Exception e) {
            logger.error("xxe except: {}", e.getClass().getSimpleName());
            return EXCEPT;
        }

        return "xmlReader xxe security code";
    }


    @RequestMapping(value = "/SAXBuilder/vuln", method = RequestMethod.POST)
    public String SAXBuilderVuln(HttpServletRequest request) {
        String xml = rebuildXml(request);
        try {
            SAXBuilder builder = secureSaxBuilder();
            // org.jdom2.Document document
            builder.build(new InputSource(new StringReader(xml)));
            return "SAXBuilder xxe vuln code";
        } catch (Exception e) {
            logger.error("xxe except: {}", e.getClass().getSimpleName());
            return EXCEPT;
        }
    }

    @RequestMapping(value = "/SAXBuilder/sec", method = RequestMethod.POST)
    public String SAXBuilderSec(HttpServletRequest request) {
        String xml = rebuildXml(request);
        try {
            SAXBuilder builder = secureSaxBuilder();
            // org.jdom2.Document document
            builder.build(new InputSource(new StringReader(xml)));

        } catch (Exception e) {
            logger.error("xxe except: {}", e.getClass().getSimpleName());
            return EXCEPT;
        }

        return "SAXBuilder xxe security code";
    }

    @RequestMapping(value = "/SAXReader/vuln", method = RequestMethod.POST)
    public String SAXReaderVuln(HttpServletRequest request) {
        String xml = rebuildXml(request);
        try {
            SAXReader reader = secureSaxReader();
            // org.dom4j.Document document
            reader.read(new InputSource(new StringReader(xml))); // cause xxe

        } catch (Exception e) {
            logger.error("xxe except: {}", e.getClass().getSimpleName());
            return EXCEPT;
        }

        return "SAXReader xxe vuln code";
    }

    @RequestMapping(value = "/SAXReader/sec", method = RequestMethod.POST)
    public String SAXReaderSec(HttpServletRequest request) {
        String xml = rebuildXml(request);
        try {
            SAXReader reader = secureSaxReader();
            // org.dom4j.Document document
            reader.read(new InputSource(new StringReader(xml)));
        } catch (Exception e) {
            logger.error("xxe except: {}", e.getClass().getSimpleName());
            return EXCEPT;
        }
        return "SAXReader xxe security code";
    }

    @RequestMapping(value = "/SAXParser/vuln", method = RequestMethod.POST)
    public String SAXParserVuln(HttpServletRequest request) {
        String xml = rebuildXml(request);
        try {
            SAXParser parser = secureSaxParser();
            parser.parse(new InputSource(new StringReader(xml)), new DefaultHandler());  // parse xml

            return "SAXParser xxe vuln code";
        } catch (Exception e) {
            logger.error("xxe except: {}", e.getClass().getSimpleName());
            return EXCEPT;
        }
    }


    @RequestMapping(value = "/SAXParser/sec", method = RequestMethod.POST)
    public String SAXParserSec(HttpServletRequest request) {
        String xml = rebuildXml(request);
        try {
            SAXParser parser = secureSaxParser();
            parser.parse(new InputSource(new StringReader(xml)), new DefaultHandler());  // parse xml
        } catch (Exception e) {
            logger.error("xxe except: {}", e.getClass().getSimpleName());
            return EXCEPT;
        }
        return "SAXParser xxe security code";
    }


    @RequestMapping(value = "/Digester/vuln", method = RequestMethod.POST)
    public String DigesterVuln(HttpServletRequest request) {
        String xml = rebuildXml(request);
        try {
            Digester digester = secureDigester();
            digester.parse(new StringReader(xml));  // parse xml
        } catch (Exception e) {
            logger.error("xxe except: {}", e.getClass().getSimpleName());
            return EXCEPT;
        }
        return "Digester xxe vuln code";
    }

    @RequestMapping(value = "/Digester/sec", method = RequestMethod.POST)
    public String DigesterSec(HttpServletRequest request) {
        String xml = rebuildXml(request);
        try {
            Digester digester = secureDigester();
            digester.parse(new StringReader(xml));  // parse xml

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
        String xml = rebuildXml(request);
        try {
            DocumentBuilderFactory dbf = secureDocumentBuilderFactory();
            DocumentBuilder db = dbf.newDocumentBuilder();
            StringReader sr = new StringReader(xml);
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
        String xml = rebuildXml(request);
        try {
            DocumentBuilderFactory dbf = secureDocumentBuilderFactory();
            dbf.setNamespaceAware(true);
            DocumentBuilder db = dbf.newDocumentBuilder();
            StringReader sr = new StringReader(xml);
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
        String xml = rebuildXml(request);
        try {
            DocumentBuilderFactory dbf = secureDocumentBuilderFactory();
            dbf.setNamespaceAware(true);

            DocumentBuilder db = dbf.newDocumentBuilder();
            StringReader sr = new StringReader(xml);
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
        String xml = rebuildXml(request);
        try {
            XMLReader xmlReader = secureXmlReader();
            xmlReader.parse(new InputSource(new StringReader(xml)));

        } catch (Exception e) {
            logger.error("xxe except: {}", e.getClass().getSimpleName());
            return EXCEPT;
        }

        return "XMLReader xxe vuln code";
    }


    @PostMapping("/XMLReader/sec")
    public String XMLReaderSec(HttpServletRequest request) {
        String xml = rebuildXml(request);
        try {
            XMLReader xmlReader = secureXmlReader();
            xmlReader.parse(new InputSource(new StringReader(xml)));

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
        String xml = rebuildXml(req);
        try {
            DocumentHelper.parseText(xml); // parse xml
        } catch (Exception e) {
            logger.error("xxe except: {}", e.getClass().getSimpleName());
            return EXCEPT;
        }

        return "DocumentHelper xxe vuln code";
    }


    private static final int MAX_BODY_BYTES = 1024 * 1024;
    private static final String NAME_ALPHABET =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.:-";

    private static final String NAME_RE = "[A-Za-z_][A-Za-z0-9_.:-]{0,63}";
    private static final String CTRL = "\\x00-\\x08\\x0B\\x0C\\x0E-\\x1F";
    private static final String ATTR_RE = "\\s+" + NAME_RE + "\\s*=\\s*(?:\"[^\"<&" + CTRL + "]*\"|'[^'<&" + CTRL + "]*')";

    /** Leading xml declaration (dropped when the document is rebuilt). */
    private static final Pattern XML_DECL = Pattern.compile(
            "^\\s*<\\?xml\\s+version\\s*=\\s*[\"']1\\.[0-9][\"']"
                    + "(?:\\s+encoding\\s*=\\s*[\"'][A-Za-z][A-Za-z0-9._-]{0,40}[\"'])?"
                    + "(?:\\s+standalone\\s*=\\s*[\"'](?:yes|no)[\"'])?\\s*\\?>");

    /**
     * One token of the accepted xml subset. Groups: 1 end-tag slash, 2 element name, 3 attributes,
     * 4 empty-element slash, 5 text, 6 predefined entity name. Everything else (DOCTYPE, ENTITY, CDATA,
     * comments, processing instructions, other entity or character references) does not match.
     */
    private static final Pattern XML_TOKEN = Pattern.compile(
            "<(/?)(" + NAME_RE + ")((?:" + ATTR_RE + ")*)\\s*(/?)>"
                    + "|([^<&" + CTRL + "]+)"
                    + "|&(amp|lt|gt|quot|apos);");
    private static final Pattern XML_ATTR = Pattern.compile(
            "\\s+(" + NAME_RE + ")\\s*=\\s*(?:\"([^\"]*)\"|'([^']*)')");

    /** Request answered with HTTP 400 and a fixed reason, never echoing the payload. */
    @ResponseStatus(value = HttpStatus.BAD_REQUEST, reason = "invalid xml payload")
    public static class InvalidXmlPayloadException extends RuntimeException {
        private static final long serialVersionUID = 1L;
    }

    private static String predefinedEntity(String name) {
        switch (name) {
            case "amp":
                return "&amp;";
            case "lt":
                return "&lt;";
            case "gt":
                return "&gt;";
            case "quot":
                return "&quot;";
            default:
                return "&apos;";
        }
    }

    /**
     * Read the request body once (size capped) and validate it against a strict pattern for the simple
     * xml documents the demo endpoints accept: optional xml declaration, elements with quoted attributes,
     * text and the five predefined entities. The raw body is never handed to an xml parser. A fresh
     * document is rebuilt from it: element and attribute names are copied from the constant
     * NAME_ALPHABET and text/attribute values are escaped with HtmlUtils.htmlEscape.
     * Any other payload is rejected with HTTP 400.
     */
    private static String rebuildXml(HttpServletRequest request) {
        String body;
        try {
            body = WebUtils.getRequestBody(request, MAX_BODY_BYTES);
        } catch (IOException e) {
            throw new InvalidXmlPayloadException();
        }
        if (body == null || body.isEmpty()) {
            throw new InvalidXmlPayloadException();
        }
        int pos = 0;
        if (body.charAt(0) == '\uFEFF') {
            pos = 1;
        }
        Matcher decl = XML_DECL.matcher(body);
        decl.region(pos, body.length());
        if (decl.lookingAt()) {
            pos = decl.end();
        }

        StringBuilder out = new StringBuilder(body.length() + 16);
        Matcher m = XML_TOKEN.matcher(body);
        int len = body.length();
        while (pos < len) {
            m.region(pos, len);
            boolean matched;
            try {
                matched = m.lookingAt();
            } catch (StackOverflowError e) {
                matched = false;
            }
            if (!matched) {
                throw new InvalidXmlPayloadException();
            }
            pos = m.end();
            if (m.group(2) != null) {
                String name = SecurityUtil.copyAllowedChars(m.group(2), NAME_ALPHABET);
                if (name == null) {
                    throw new InvalidXmlPayloadException();
                }
                if (!m.group(1).isEmpty()) {
                    if (!m.group(3).isEmpty() || !m.group(4).isEmpty()) {
                        throw new InvalidXmlPayloadException();
                    }
                    out.append("</").append(name).append('>');
                    continue;
                }
                out.append('<').append(name);
                Matcher attr = XML_ATTR.matcher(m.group(3));
                while (attr.find()) {
                    String attrName = SecurityUtil.copyAllowedChars(attr.group(1), NAME_ALPHABET);
                    String attrValue = attr.group(2) != null ? attr.group(2) : attr.group(3);
                    if (attrName == null) {
                        throw new InvalidXmlPayloadException();
                    }
                    out.append(' ').append(attrName).append("=\"")
                            .append(HtmlUtils.htmlEscape(attrValue, "UTF-8")).append('"');
                }
                out.append(m.group(4).isEmpty() ? ">" : "/>");
            } else if (m.group(5) != null) {
                out.append(HtmlUtils.htmlEscape(m.group(5), "UTF-8"));
            } else {
                out.append(predefinedEntity(m.group(6)));
            }
        }
        return out.toString();
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
                logger.debug("xxe response helper visited a child node");
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