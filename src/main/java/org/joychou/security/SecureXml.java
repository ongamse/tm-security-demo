package org.joychou.security;

import org.apache.commons.digester3.Digester;
import org.dom4j.io.SAXReader;
import org.jdom2.input.SAXBuilder;
import org.xml.sax.SAXException;
import org.xml.sax.XMLReader;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;
import javax.xml.stream.XMLInputFactory;
import java.util.Locale;

/**
 * Factory helpers that build XML parsers hardened against XXE (CWE-611),
 * plus a pre-parse check that rejects DTD / entity declarations.
 */
public final class SecureXml {

    private static final String DISALLOW_DOCTYPE = "http://apache.org/xml/features/disallow-doctype-decl";
    private static final String GENERAL_ENTITIES = "http://xml.org/sax/features/external-general-entities";
    private static final String PARAMETER_ENTITIES = "http://xml.org/sax/features/external-parameter-entities";
    private static final String LOAD_EXTERNAL_DTD = "http://apache.org/xml/features/nonvalidating/load-external-dtd";

    private SecureXml() {
    }

    /**
     * Reject any XML text that carries a DOCTYPE or ENTITY declaration.
     * Call this on untrusted input before it reaches a parser.
     *
     * @return the same text when it is acceptable
     * @throws IllegalArgumentException if a DOCTYPE or ENTITY declaration is present
     */
    public static String requireNoDtd(String xml) {
        if (xml == null) {
            return null;
        }
        String upper = xml.toUpperCase(Locale.ROOT);
        if (upper.contains("<!DOCTYPE") || upper.contains("<!ENTITY")) {
            throw new IllegalArgumentException("DOCTYPE and ENTITY declarations are not allowed");
        }
        return xml;
    }

    public static DocumentBuilderFactory newDocumentBuilderFactory() throws ParserConfigurationException {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        dbf.setFeature(DISALLOW_DOCTYPE, true);
        dbf.setFeature(GENERAL_ENTITIES, false);
        dbf.setFeature(PARAMETER_ENTITIES, false);
        dbf.setFeature(LOAD_EXTERNAL_DTD, false);
        dbf.setXIncludeAware(false);
        dbf.setExpandEntityReferences(false);
        try {
            dbf.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
            dbf.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
        } catch (IllegalArgumentException ignored) {
            // JAXP implementation without these attributes; the features above still apply.
        }
        return dbf;
    }

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

    public static SAXParser newSAXParser() throws ParserConfigurationException, SAXException {
        SAXParser parser = newSAXParserFactory().newSAXParser();
        try {
            parser.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, "");
            parser.setProperty(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
        } catch (SAXException ignored) {
            // JAXP implementation without these properties; the features above still apply.
        }
        return parser;
    }

    public static XMLReader newXMLReader() throws ParserConfigurationException, SAXException {
        return newSAXParser().getXMLReader();
    }

    public static XMLInputFactory newXMLInputFactory() {
        XMLInputFactory xif = XMLInputFactory.newInstance();
        xif.setProperty(XMLInputFactory.SUPPORT_DTD, false);
        xif.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
        xif.setProperty(XMLInputFactory.IS_REPLACING_ENTITY_REFERENCES, false);
        return xif;
    }

    /** jdom2 builder with DTDs and external entities disabled. */
    public static SAXBuilder newSAXBuilder() {
        SAXBuilder builder = new SAXBuilder();
        builder.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        builder.setFeature(DISALLOW_DOCTYPE, true);
        builder.setFeature(GENERAL_ENTITIES, false);
        builder.setFeature(PARAMETER_ENTITIES, false);
        builder.setFeature(LOAD_EXTERNAL_DTD, false);
        builder.setExpandEntities(false);
        return builder;
    }

    /** dom4j reader with DTDs and external entities disabled. */
    public static SAXReader newSAXReader() throws SAXException {
        SAXReader reader = new SAXReader();
        reader.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        reader.setFeature(DISALLOW_DOCTYPE, true);
        reader.setFeature(GENERAL_ENTITIES, false);
        reader.setFeature(PARAMETER_ENTITIES, false);
        reader.setFeature(LOAD_EXTERNAL_DTD, false);
        reader.setIncludeExternalDTDDeclarations(false);
        reader.setIncludeInternalDTDDeclarations(false);
        return reader;
    }

    /** commons-digester3 with DTDs and external entities disabled. */
    public static Digester newDigester() throws ParserConfigurationException, SAXException {
        Digester digester = new Digester();
        digester.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        digester.setFeature(DISALLOW_DOCTYPE, true);
        digester.setFeature(GENERAL_ENTITIES, false);
        digester.setFeature(PARAMETER_ENTITIES, false);
        digester.setFeature(LOAD_EXTERNAL_DTD, false);
        return digester;
    }
}
