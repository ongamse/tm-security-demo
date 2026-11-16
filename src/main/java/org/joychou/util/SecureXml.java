package org.joychou.util;

import org.apache.commons.digester3.Digester;
import org.dom4j.io.SAXReader;
import org.jdom2.input.SAXBuilder;
import org.xml.sax.SAXException;
import org.xml.sax.XMLReader;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.parsers.SAXParserFactory;

/**
 * Single place that builds hardened XML parsers (no DOCTYPE, no external entities,
 * no XInclude, no external DTD/schema access). Every parse of request data must go
 * through one of these factories.
 */
public final class SecureXml {

    private static final String DISALLOW_DOCTYPE = "http://apache.org/xml/features/disallow-doctype-decl";
    private static final String GENERAL_ENTITIES = "http://xml.org/sax/features/external-general-entities";
    private static final String PARAMETER_ENTITIES = "http://xml.org/sax/features/external-parameter-entities";
    private static final String LOAD_EXTERNAL_DTD = "http://apache.org/xml/features/nonvalidating/load-external-dtd";

    private SecureXml() {
    }

    /** Hardened DocumentBuilderFactory (namespace aware, XInclude off, entity references not expanded). */
    public static DocumentBuilderFactory newDocumentBuilderFactory() throws ParserConfigurationException {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        dbf.setFeature(DISALLOW_DOCTYPE, true);
        dbf.setFeature(GENERAL_ENTITIES, false);
        dbf.setFeature(PARAMETER_ENTITIES, false);
        dbf.setFeature(LOAD_EXTERNAL_DTD, false);
        dbf.setXIncludeAware(false);
        dbf.setExpandEntityReferences(false);
        dbf.setNamespaceAware(true);
        try {
            dbf.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
            dbf.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
        } catch (IllegalArgumentException ignored) {
            // JAXP 1.5 attributes not supported by this parser; the features above still apply.
        }
        return dbf;
    }

    /** Hardened SAXParserFactory (XInclude off). */
    public static SAXParserFactory newSAXParserFactory() throws ParserConfigurationException, SAXException {
        SAXParserFactory spf = SAXParserFactory.newInstance();
        spf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        spf.setFeature(DISALLOW_DOCTYPE, true);
        spf.setFeature(GENERAL_ENTITIES, false);
        spf.setFeature(PARAMETER_ENTITIES, false);
        spf.setFeature(LOAD_EXTERNAL_DTD, false);
        spf.setXIncludeAware(false);
        return spf;
    }

    /** Hardened XMLReader built from the hardened SAXParserFactory. */
    public static XMLReader newXMLReader() throws ParserConfigurationException, SAXException {
        XMLReader reader = newSAXParserFactory().newSAXParser().getXMLReader();
        reader.setFeature(DISALLOW_DOCTYPE, true);
        reader.setFeature(GENERAL_ENTITIES, false);
        reader.setFeature(PARAMETER_ENTITIES, false);
        try {
            reader.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, "");
            reader.setProperty(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
        } catch (SAXException ignored) {
            // JAXP 1.5 properties not supported by this parser; the features above still apply.
        }
        return reader;
    }

    /** dom4j SAXReader backed by the hardened XMLReader. */
    public static SAXReader newSAXReader() throws ParserConfigurationException, SAXException {
        return new SAXReader(newXMLReader());
    }

    /** commons-digester Digester backed by the hardened XMLReader. */
    public static Digester newDigester() throws ParserConfigurationException, SAXException {
        return new Digester(newXMLReader());
    }

    /** JDOM2 SAXBuilder with DOCTYPE and external entities disabled. */
    public static SAXBuilder newSAXBuilder() {
        SAXBuilder builder = new SAXBuilder();
        builder.setFeature(DISALLOW_DOCTYPE, true);
        builder.setFeature(GENERAL_ENTITIES, false);
        builder.setFeature(PARAMETER_ENTITIES, false);
        builder.setExpandEntities(false);
        return builder;
    }
}
