package org.joychou.util;

import org.xml.sax.SAXException;
import org.xml.sax.XMLReader;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.parsers.SAXParserFactory;

/**
 * Factories for XML parsers hardened against XXE (CWE-611).
 * Fail closed: if any protection cannot be applied an exception is thrown,
 * so a parser is never returned in a partially hardened state.
 */
public final class XmlSecurity {

    private static final String DISALLOW_DOCTYPE = "http://apache.org/xml/features/disallow-doctype-decl";
    private static final String EXTERNAL_GENERAL_ENTITIES = "http://xml.org/sax/features/external-general-entities";
    private static final String EXTERNAL_PARAMETER_ENTITIES = "http://xml.org/sax/features/external-parameter-entities";
    private static final String LOAD_EXTERNAL_DTD = "http://apache.org/xml/features/nonvalidating/load-external-dtd";

    private XmlSecurity() {
    }

    public static DocumentBuilderFactory newDocumentBuilderFactory() throws ParserConfigurationException {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        dbf.setFeature(DISALLOW_DOCTYPE, true);
        dbf.setFeature(EXTERNAL_GENERAL_ENTITIES, false);
        dbf.setFeature(EXTERNAL_PARAMETER_ENTITIES, false);
        dbf.setFeature(LOAD_EXTERNAL_DTD, false);
        dbf.setXIncludeAware(false);
        dbf.setExpandEntityReferences(false);
        return dbf;
    }

    public static SAXParserFactory newSAXParserFactory() throws ParserConfigurationException, SAXException {
        SAXParserFactory spf = SAXParserFactory.newInstance();
        spf.setNamespaceAware(true);
        spf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        spf.setFeature(DISALLOW_DOCTYPE, true);
        spf.setFeature(EXTERNAL_GENERAL_ENTITIES, false);
        spf.setFeature(EXTERNAL_PARAMETER_ENTITIES, false);
        spf.setFeature(LOAD_EXTERNAL_DTD, false);
        spf.setXIncludeAware(false);
        return spf;
    }

    /**
     * XMLReader created from a hardened factory; the features are also asserted on the reader itself.
     */
    public static XMLReader newXMLReader() throws ParserConfigurationException, SAXException {
        XMLReader reader = newSAXParserFactory().newSAXParser().getXMLReader();
        reader.setFeature(DISALLOW_DOCTYPE, true);
        reader.setFeature(EXTERNAL_GENERAL_ENTITIES, false);
        reader.setFeature(EXTERNAL_PARAMETER_ENTITIES, false);
        return reader;
    }
}
