package org.joychou.util;

import org.jdom2.JDOMException;
import org.jdom2.input.sax.XMLReaderJDOMFactory;
import org.xml.sax.SAXException;
import org.xml.sax.SAXNotRecognizedException;
import org.xml.sax.SAXNotSupportedException;
import org.xml.sax.XMLReader;

import javax.xml.XMLConstants;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;

/**
 * Shared builder of hardened SAX parsers: DOCTYPE is rejected, external entities / DTDs are never
 * loaded, and JAXP external access is denied. Every parser that handles untrusted XML should come
 * from here so the configuration lives on the exact factory / parser object that parses the input.
 */
public final class XmlSecurity {

    private static final String DISALLOW_DOCTYPE = "http://apache.org/xml/features/disallow-doctype-decl";
    private static final String EXTERNAL_GENERAL = "http://xml.org/sax/features/external-general-entities";
    private static final String EXTERNAL_PARAMETER = "http://xml.org/sax/features/external-parameter-entities";
    private static final String LOAD_EXTERNAL_DTD = "http://apache.org/xml/features/nonvalidating/load-external-dtd";

    private XmlSecurity() {
    }

    /** SAXParserFactory with all XXE protections enabled. */
    public static SAXParserFactory newSecureSaxParserFactory() throws ParserConfigurationException, SAXException {
        SAXParserFactory spf = SAXParserFactory.newInstance();
        spf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        spf.setFeature(DISALLOW_DOCTYPE, true);
        spf.setFeature(EXTERNAL_GENERAL, false);
        spf.setFeature(EXTERNAL_PARAMETER, false);
        spf.setFeature(LOAD_EXTERNAL_DTD, false);
        spf.setXIncludeAware(false);
        spf.setValidating(false);
        return spf;
    }

    /** SAXParser (created from a secure factory) with JAXP external access denied. */
    public static SAXParser newSecureSaxParser() throws ParserConfigurationException, SAXException {
        SAXParser parser = newSecureSaxParserFactory().newSAXParser();
        denyExternalAccess(parser);
        XMLReader reader = parser.getXMLReader();
        reader.setFeature(DISALLOW_DOCTYPE, true);
        reader.setFeature(EXTERNAL_GENERAL, false);
        reader.setFeature(EXTERNAL_PARAMETER, false);
        return parser;
    }

    /** Hardened XMLReader. */
    public static XMLReader newSecureXmlReader() throws ParserConfigurationException, SAXException {
        return newSecureSaxParser().getXMLReader();
    }

    /** JDOM2 reader factory that hands out hardened XMLReaders. */
    public static XMLReaderJDOMFactory secureJdomReaderFactory() {
        return new XMLReaderJDOMFactory() {
            @Override
            public XMLReader createXMLReader() throws JDOMException {
                try {
                    return newSecureXmlReader();
                } catch (ParserConfigurationException | SAXException e) {
                    throw new JDOMException("Unable to create secure XMLReader", e);
                }
            }

            @Override
            public boolean isValidating() {
                return false;
            }
        };
    }

    private static void denyExternalAccess(SAXParser parser) throws SAXException {
        String[] props = {XMLConstants.ACCESS_EXTERNAL_DTD, XMLConstants.ACCESS_EXTERNAL_SCHEMA};
        for (String prop : props) {
            try {
                parser.setProperty(prop, "");
            } catch (SAXNotRecognizedException | SAXNotSupportedException ignored) {
                // Parser predates JAXP 1.5; DOCTYPE is already rejected outright.
            }
        }
    }
}
