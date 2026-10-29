package org.joychou.controller;

import org.joychou.security.LogSanitizer;
import org.springframework.web.util.HtmlUtils;
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

import org.joychou.security.SecureXml;
import org.xmlbeam.annotation.XBRead;

/**
 * Java xxe vuln and security code.
 * <p>
 * Every endpoint parses the request body through the single hardened entry point
 * {@link SecureXml#parse(HttpServletRequest, boolean)}: size capped, DOCTYPE / ENTITY rejected,
 * DTDs and external entities disabled on the parser. Endpoints only consume the parsed DOM.
 *
 * @author JoyChou @2017-12-22
 */

@RestController
@RequestMapping("/xxe")
public class XXE {

    private static final Logger logger = LoggerFactory.getLogger(XXE.class);
    private static final String EXCEPT = "xxe except";

    /** Parse the request body with the hardened parser; an empty body is an error. */
    private static Document parseBody(HttpServletRequest request, boolean namespaceAware) throws Exception {
        Document document = SecureXml.parse(request, namespaceAware);
        if (document == null) {
            throw new IllegalArgumentException("Empty XML body");
        }
        return document;
    }

    @PostMapping("/xmlReader/vuln")
    public String xmlReaderVuln(HttpServletRequest request) {
        try {
            parseBody(request, false);
            return "xmlReader xxe vuln code";
        } catch (Exception e) {
            logger.error("Operation failed.", e);
            return EXCEPT;
        }
    }


    @RequestMapping(value = "/xmlReader/sec", method = RequestMethod.POST)
    public String xmlReaderSec(HttpServletRequest request) {
        try {
            parseBody(request, false);
        } catch (Exception e) {
            logger.error("Operation failed.", e);
            return EXCEPT;
        }

        return "xmlReader xxe security code";
    }


    @RequestMapping(value = "/SAXBuilder/vuln", method = RequestMethod.POST)
    public String SAXBuilderVuln(HttpServletRequest request) {
        try {
            parseBody(request, false);
            return "SAXBuilder xxe vuln code";
        } catch (Exception e) {
            logger.error("Operation failed.", e);
            return EXCEPT;
        }
    }

    @RequestMapping(value = "/SAXBuilder/sec", method = RequestMethod.POST)
    public String SAXBuilderSec(HttpServletRequest request) {
        try {
            parseBody(request, false);
        } catch (Exception e) {
            logger.error("Operation failed.", e);
            return EXCEPT;
        }

        return "SAXBuilder xxe security code";
    }

    @RequestMapping(value = "/SAXReader/vuln", method = RequestMethod.POST)
    public String SAXReaderVuln(HttpServletRequest request) {
        try {
            parseBody(request, false);
        } catch (Exception e) {
            logger.error("Operation failed.", e);
            return EXCEPT;
        }

        return "SAXReader xxe vuln code";
    }

    @RequestMapping(value = "/SAXReader/sec", method = RequestMethod.POST)
    public String SAXReaderSec(HttpServletRequest request) {
        try {
            parseBody(request, false);
        } catch (Exception e) {
            logger.error("Operation failed.", e);
            return EXCEPT;
        }
        return "SAXReader xxe security code";
    }

    @RequestMapping(value = "/SAXParser/vuln", method = RequestMethod.POST)
    public String SAXParserVuln(HttpServletRequest request) {
        try {
            parseBody(request, false);
            return "SAXParser xxe vuln code";
        } catch (Exception e) {
            logger.error("Operation failed.", e);
            return EXCEPT;
        }
    }


    @RequestMapping(value = "/SAXParser/sec", method = RequestMethod.POST)
    public String SAXParserSec(HttpServletRequest request) {
        try {
            parseBody(request, false);
        } catch (Exception e) {
            logger.error("Operation failed.", e);
            return EXCEPT;
        }
        return "SAXParser xxe security code";
    }


    @RequestMapping(value = "/Digester/vuln", method = RequestMethod.POST)
    public String DigesterVuln(HttpServletRequest request) {
        try {
            parseBody(request, false);
        } catch (Exception e) {
            logger.error("Operation failed.", e);
            return EXCEPT;
        }
        return "Digester xxe vuln code";
    }

    @RequestMapping(value = "/Digester/sec", method = RequestMethod.POST)
    public String DigesterSec(HttpServletRequest request) {
        try {
            parseBody(request, false);

            return "Digester xxe security code";
        } catch (Exception e) {
            logger.error("Operation failed.", e);
            return EXCEPT;
        }
    }


    /**
     * The body is read as bytes so UTF-16 encoded documents are handled (and checked) correctly.
     */
    @RequestMapping(value = "/DocumentBuilder/vuln", method = RequestMethod.POST)
    public String DocumentBuilderVuln(HttpServletRequest request) {
        try {
            Document document = parseBody(request, false);

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
            logger.error("XML parsing failed.", e);
            return "Request failed.";
        }
    }

    @RequestMapping(value = "/DocumentBuilder/Sec", method = RequestMethod.POST)
    public String DocumentBuilderSec(HttpServletRequest request) {
        try {
            parseBody(request, false);
        } catch (Exception e) {
            logger.error("Operation failed.", e);
            return EXCEPT;
        }
        return "DocumentBuilder xxe security code";
    }


    @RequestMapping(value = "/DocumentBuilder/xinclude/vuln", method = RequestMethod.POST)
    public String DocumentBuilderXincludeVuln(HttpServletRequest request) {
        try {
            Document document = parseBody(request, true);

            NodeList rootNodeList = document.getChildNodes();
            response(rootNodeList);

            return "DocumentBuilder xinclude xxe vuln code";
        } catch (Exception e) {
            logger.error("Operation failed.", e);
            return EXCEPT;
        }
    }


    @RequestMapping(value = "/DocumentBuilder/xinclude/sec", method = RequestMethod.POST)
    public String DocumentBuilderXincludeSec(HttpServletRequest request) {
        try {
            Document document = parseBody(request, true);

            NodeList rootNodeList = document.getChildNodes();
            response(rootNodeList);
        } catch (Exception e) {
            logger.error("Operation failed.", e);
            return EXCEPT;
        }
        return "DocumentBuilder xinclude xxe vuln code";
    }


    @PostMapping("/XMLReader/vuln")
    public String XMLReaderVuln(HttpServletRequest request) {
        try {
            parseBody(request, false);
        } catch (Exception e) {
            logger.error("Operation failed.", e);
            return EXCEPT;
        }

        return "XMLReader xxe vuln code";
    }


    @PostMapping("/XMLReader/sec")
    public String XMLReaderSec(HttpServletRequest request) {
        try {
            parseBody(request, false);
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
            parseBody(req, false);
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
                logger.error("Operation failed.", e);
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
