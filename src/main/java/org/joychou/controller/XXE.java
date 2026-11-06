package org.joychou.controller;

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

import java.io.*;
import java.util.Locale;

import org.xml.sax.InputSource;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.joychou.security.SecurityUtil;
import org.joychou.util.WebUtils;
import org.xmlbeam.annotation.XBRead;

/**
 * Java xxe vuln and security code.
 *
 * Every endpoint that parses a request body goes through {@link #parseXml(String)}, which builds a fully
 * hardened parser and is only reached after {@link #hasDtdOrEntity(String)} refused DOCTYPE / ENTITY input.
 *
 * @author JoyChou @2017-12-22
 */

@RestController
@RequestMapping("/xxe")
public class XXE {

    private static final Logger logger = LoggerFactory.getLogger(XXE.class);
    private static final String EXCEPT = "xxe except";
    private static final String REFUSED = "400 bad request: DOCTYPE and ENTITY declarations are not allowed";

    @PostMapping("/xmlReader/vuln")
    public String xmlReaderVuln(HttpServletRequest request) {
        try {
            String body = WebUtils.getRequestBody(request);
            logger.info(SecurityUtil.logSafe(body));
            if (hasDtdOrEntity(body)) {
                return REFUSED;
            }
            parseXml(body);  // parse xml
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
            logger.info(SecurityUtil.logSafe(body));
            if (hasDtdOrEntity(body)) {
                return REFUSED;
            }
            parseXml(body);  // parse xml

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
            logger.info(SecurityUtil.logSafe(body));
            if (hasDtdOrEntity(body)) {
                return REFUSED;
            }
            parseXml(body);
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
            logger.info(SecurityUtil.logSafe(body));
            if (hasDtdOrEntity(body)) {
                return REFUSED;
            }
            parseXml(body);

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
            logger.info(SecurityUtil.logSafe(body));
            if (hasDtdOrEntity(body)) {
                return REFUSED;
            }
            parseXml(body);

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
            logger.info(SecurityUtil.logSafe(body));
            if (hasDtdOrEntity(body)) {
                return REFUSED;
            }
            parseXml(body);
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
            logger.info(SecurityUtil.logSafe(body));
            if (hasDtdOrEntity(body)) {
                return REFUSED;
            }
            parseXml(body);  // parse xml

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
            logger.info(SecurityUtil.logSafe(body));
            if (hasDtdOrEntity(body)) {
                return REFUSED;
            }
            parseXml(body);  // parse xml
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
            logger.info(SecurityUtil.logSafe(body));
            if (hasDtdOrEntity(body)) {
                return REFUSED;
            }
            parseXml(body);  // parse xml
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
            logger.info(SecurityUtil.logSafe(body));
            if (hasDtdOrEntity(body)) {
                return REFUSED;
            }
            parseXml(body);  // parse xml

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
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
            dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
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
            e.printStackTrace();
            logger.error(SecurityUtil.logSafe(e.toString()));
            return EXCEPT;
        }
    }

    @RequestMapping(value = "/DocumentBuilder/Sec", method = RequestMethod.POST)
    public String DocumentBuilderSec(HttpServletRequest request) {
        try {
            String body = WebUtils.getRequestBody(request);
            logger.info(SecurityUtil.logSafe(body));
            if (hasDtdOrEntity(body)) {
                return REFUSED;
            }
            parseXml(body);  // parse xml
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
            logger.info(SecurityUtil.logSafe(body));
            if (hasDtdOrEntity(body)) {
                return REFUSED;
            }
            Document document = parseXml(body);  // parse xml

            NodeList rootNodeList = document.getChildNodes();
            response(rootNodeList);

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
            logger.info(SecurityUtil.logSafe(body));
            if (hasDtdOrEntity(body)) {
                return REFUSED;
            }
            Document document = parseXml(body);  // parse xml

            NodeList rootNodeList = document.getChildNodes();
            response(rootNodeList);
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
            logger.info(SecurityUtil.logSafe(body));
            if (hasDtdOrEntity(body)) {
                return REFUSED;
            }
            parseXml(body);

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
            logger.info(SecurityUtil.logSafe(body));
            if (hasDtdOrEntity(body)) {
                return REFUSED;
            }
            parseXml(body);

        } catch (Exception e) {
            logger.error(e.toString());
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
            String body = WebUtils.getRequestBody(req);
            if (hasDtdOrEntity(body)) {
                return REFUSED;
            }
            parseXml(body); // parse xml
        } catch (Exception e) {
            logger.error(e.toString());
            return EXCEPT;
        }

        return "DocumentHelper xxe vuln code";
    }


    /**
     * Returns true when the text declares a DOCTYPE or an ENTITY (case-insensitive); such bodies are refused.
     */
    private static boolean hasDtdOrEntity(String xml) {
        if (xml == null) {
            return false;
        }
        String lower = xml.toLowerCase(Locale.ROOT);
        return lower.contains("<!doctype") || lower.contains("<!entity");
    }

    /**
     * Single hardened parse entry point: DTDs, external entities, XInclude and entity expansion are all disabled
     * on the factory created here, and the parser only receives an InputSource over an in-memory StringReader.
     */
    private static Document parseXml(String xml) throws Exception {
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
        dbf.setNamespaceAware(true);
        DocumentBuilder db = dbf.newDocumentBuilder();
        try (StringReader reader = new StringReader(xml)) {
            return db.parse(new InputSource(reader));
        }
    }


    private static void response(NodeList rootNodeList){
        for (int i = 0; i < rootNodeList.getLength(); i++) {
            Node rootNode = rootNodeList.item(i);
            NodeList xxe = rootNode.getChildNodes();
            for (int j = 0; j < xxe.getLength(); j++) {
                Node xxeNode = xxe.item(j);
                // 测试不能blind xxe，所以强行加了一个回显
                logger.info("xxeNode: " + SecurityUtil.logSafe(xxeNode.getNodeValue()));
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
                logger.info(SecurityUtil.logSafe(user.toString()));
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
