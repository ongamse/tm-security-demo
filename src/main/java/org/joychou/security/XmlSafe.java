package org.joychou.security;

import org.apache.commons.digester3.Digester;
import org.dom4j.io.SAXReader;
import org.jdom2.input.SAXBuilder;
import org.xml.sax.EntityResolver;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.XMLReader;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.parsers.SAXParserFactory;
import javax.xml.stream.XMLInputFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.util.Locale;

/**
 * Single place that builds every XML parser used for untrusted input.
 * All parsers reject DOCTYPE declarations, never resolve external entities / DTDs / schemas,
 * disable XInclude and resolve any remaining entity request to an empty source.
 */
public final class XmlSafe {

    private static final String DISALLOW_DOCTYPE = "http://apache.org/xml/features/disallow-doctype-decl";
    private static final String EXTERNAL_GENERAL = "http://xml.org/sax/features/external-general-entities";
    private static final String EXTERNAL_PARAMETER = "http://xml.org/sax/features/external-parameter-entities";
    private static final String LOAD_EXTERNAL_DTD = "http://apache.org/xml/features/nonvalidating/load-external-dtd";

    /** Resolver that never touches the network or file system. */
    private static final EntityResolver NO_OP_RESOLVER = new EntityResolver() {
        @Override
        public InputSource resolveEntity(String publicId, String systemId) {
            return new InputSource(new StringReader(""));
        }
    };

    private XmlSafe() {
    }

    public static EntityResolver noOpEntityResolver() {
        return NO_OP_RESOLVER;
    }

    public static DocumentBuilderFactory newDocumentBuilderFactory(boolean namespaceAware)
            throws ParserConfigurationException {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(namespaceAware);
        dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        dbf.setFeature(DISALLOW_DOCTYPE, true);
        dbf.setFeature(EXTERNAL_GENERAL, false);
        dbf.setFeature(EXTERNAL_PARAMETER, false);
        trySetFeature(dbf, LOAD_EXTERNAL_DTD, false);
        dbf.setXIncludeAware(false);
        dbf.setExpandEntityReferences(false);
        trySetAttribute(dbf, XMLConstants.ACCESS_EXTERNAL_DTD);
        trySetAttribute(dbf, XMLConstants.ACCESS_EXTERNAL_SCHEMA);
        return dbf;
    }

    public static DocumentBuilder newDocumentBuilder(boolean namespaceAware) throws ParserConfigurationException {
        DocumentBuilder db = newDocumentBuilderFactory(namespaceAware).newDocumentBuilder();
        db.setEntityResolver(NO_OP_RESOLVER);
        return db;
    }

    public static SAXParserFactory newSAXParserFactory() throws ParserConfigurationException, SAXException {
        SAXParserFactory spf = SAXParserFactory.newInstance();
        spf.setNamespaceAware(true);
        spf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        spf.setFeature(DISALLOW_DOCTYPE, true);
        spf.setFeature(EXTERNAL_GENERAL, false);
        spf.setFeature(EXTERNAL_PARAMETER, false);
        try {
            spf.setFeature(LOAD_EXTERNAL_DTD, false);
        } catch (ParserConfigurationException | SAXException ignored) {
            // optional, not supported by every SAX implementation; DOCTYPE is already rejected
        }
        spf.setXIncludeAware(false);
        return spf;
    }

    /** Hardened XMLReader (also the base for SAXParser style parsing via an XMLReader). */
    public static XMLReader newXMLReader() throws ParserConfigurationException, SAXException {
        XMLReader reader = newSAXParserFactory().newSAXParser().getXMLReader();
        reader.setEntityResolver(NO_OP_RESOLVER);
        trySetProperty(reader, XMLConstants.ACCESS_EXTERNAL_DTD);
        trySetProperty(reader, XMLConstants.ACCESS_EXTERNAL_SCHEMA);
        return reader;
    }

    public static SAXBuilder newSAXBuilder() {
        SAXBuilder builder = new SAXBuilder();
        builder.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        builder.setFeature(DISALLOW_DOCTYPE, true);
        builder.setFeature(EXTERNAL_GENERAL, false);
        builder.setFeature(EXTERNAL_PARAMETER, false);
        builder.setExpandEntities(false);
        builder.setEntityResolver(NO_OP_RESOLVER);
        return builder;
    }

    public static SAXReader newSAXReader() throws SAXException {
        SAXReader reader = new SAXReader();
        reader.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        reader.setFeature(DISALLOW_DOCTYPE, true);
        reader.setFeature(EXTERNAL_GENERAL, false);
        reader.setFeature(EXTERNAL_PARAMETER, false);
        reader.setIncludeExternalDTDDeclarations(false);
        reader.setIncludeInternalDTDDeclarations(false);
        reader.setEntityResolver(NO_OP_RESOLVER);
        return reader;
    }

    public static Digester newDigester() throws ParserConfigurationException, SAXException {
        Digester digester = new Digester(newXMLReader());
        digester.setEntityResolver(NO_OP_RESOLVER);
        return digester;
    }

    public static XMLInputFactory newXMLInputFactory() {
        XMLInputFactory xif = XMLInputFactory.newInstance();
        xif.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
        xif.setProperty(XMLInputFactory.SUPPORT_DTD, false);
        return xif;
    }

    /**
     * Reject raw bytes that contain a DOCTYPE or ENTITY declaration in any common
     * encoding (NUL bytes are stripped so UTF-16 is covered too).
     */
    public static void rejectDoctype(byte[] xml) throws IOException {
        ByteArrayOutputStream stripped = new ByteArrayOutputStream(xml.length);
        for (byte b : xml) {
            if (b != 0) {
                stripped.write(b);
            }
        }
        String text = new String(stripped.toByteArray(), StandardCharsets.ISO_8859_1).toLowerCase(Locale.ROOT);
        if (text.contains("<!doctype") || text.contains("<!entity")) {
            throw new IOException("DOCTYPE / ENTITY declarations are not allowed");
        }
    }

    /**
     * Validate one untrusted XML document (raw byte scan, then hardened parse) and return a
     * freshly serialized copy that is guaranteed to carry no DTD or entity declarations.
     */
    public static byte[] sanitizeXml(byte[] xml) throws IOException {
        rejectDoctype(xml);
        try {
            DocumentBuilder db = newDocumentBuilder(true);
            org.w3c.dom.Document doc = db.parse(new InputSource(new ByteArrayInputStream(xml)));
            TransformerFactory tf = TransformerFactory.newInstance();
            tf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            try {
                tf.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
                tf.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "");
            } catch (IllegalArgumentException ignored) {
                // attribute not supported by this TransformerFactory
            }
            Transformer transformer = tf.newTransformer();
            transformer.setOutputProperty(javax.xml.transform.OutputKeys.ENCODING, "UTF-8");
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            transformer.transform(new DOMSource(doc), new StreamResult(out));
            return out.toByteArray();
        } catch (Exception e) {
            throw new IOException("Rejected unsafe or malformed XML", e);
        }
    }

    private static void trySetFeature(DocumentBuilderFactory dbf, String name, boolean value) {
        try {
            dbf.setFeature(name, value);
        } catch (ParserConfigurationException ignored) {
            // optional hardening feature; DOCTYPE is already rejected
        }
    }

    private static void trySetAttribute(DocumentBuilderFactory dbf, String name) {
        try {
            dbf.setAttribute(name, "");
        } catch (IllegalArgumentException ignored) {
            // attribute not supported by this implementation
        }
    }

    private static void trySetProperty(XMLReader reader, String name) {
        try {
            reader.setProperty(name, "");
        } catch (SAXException ignored) {
            // property not supported by this implementation
        }
    }
}
