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
import javax.xml.stream.XMLOutputFactory;
import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import javax.xml.stream.XMLStreamWriter;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.regex.Pattern;

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

    /** Upper bound (in chars) for an untrusted XML request body handled by {@link #rebuild(String)}. */
    public static final int MAX_XML_CHARS = 1024 * 1024;

    /** Any markup declaration (DOCTYPE, ENTITY, ELEMENT, ATTLIST, NOTATION) except comments and CDATA. */
    private static final Pattern MARKUP_DECLARATION = Pattern.compile("<!(?!--|\\[cdata\\[)");

    /**
     * Single entry point for untrusted XML text. The body is size-capped and scanned for DTD /
     * entity declarations and stylesheet processing instructions (after stripping BOM and NULs so
     * UTF-16 style payloads are covered), then read with the hardened StAX reader and re-serialized
     * from its events into a fresh String. Only start/end elements, attributes and character data
     * survive; comments, processing instructions and any DTD content are dropped. Callers must hand
     * only the returned value to their parser.
     *
     * @throws IOException if the input is too large, carries a DTD / entity declaration or is not
     *                     well-formed XML
     */
    public static String rebuild(String xml) throws IOException {
        if (xml == null || xml.isEmpty()) {
            throw new IOException("Empty XML body");
        }
        if (xml.length() > MAX_XML_CHARS) {
            throw new IOException("XML body too large");
        }
        String probe = xml.replace("\u0000", "").replace("\uFEFF", "").toLowerCase(Locale.ROOT);
        if (MARKUP_DECLARATION.matcher(probe).find() || probe.contains("<?xml-stylesheet")) {
            throw new IOException("DOCTYPE / ENTITY declarations are not allowed");
        }
        XMLStreamReader reader = null;
        XMLStreamWriter writer = null;
        try {
            XMLInputFactory xif = newXMLInputFactory();
            xif.setProperty(XMLInputFactory.IS_NAMESPACE_AWARE, false);
            xif.setProperty(XMLInputFactory.IS_COALESCING, true);
            reader = xif.createXMLStreamReader(new StringReader(xml));
            StringWriter out = new StringWriter(xml.length());
            writer = XMLOutputFactory.newInstance().createXMLStreamWriter(out);
            int depth = 0;
            boolean rootSeen = false;
            while (reader.hasNext()) {
                int event = reader.next();
                switch (event) {
                    case XMLStreamConstants.START_ELEMENT:
                        if (depth == 0 && rootSeen) {
                            throw new IOException("Multiple root elements");
                        }
                        rootSeen = true;
                        depth++;
                        writer.writeStartElement(reader.getLocalName());
                        for (int i = 0; i < reader.getAttributeCount(); i++) {
                            writer.writeAttribute(reader.getAttributeName(i).getLocalPart(),
                                    reader.getAttributeValue(i));
                        }
                        break;
                    case XMLStreamConstants.END_ELEMENT:
                        depth--;
                        writer.writeEndElement();
                        break;
                    case XMLStreamConstants.CHARACTERS:
                    case XMLStreamConstants.CDATA:
                    case XMLStreamConstants.SPACE:
                        if (depth > 0) {
                            writer.writeCharacters(reader.getText());
                        }
                        break;
                    default:
                        // comments, processing instructions, DTD, entity references: dropped
                        break;
                }
            }
            if (!rootSeen) {
                throw new IOException("No root element");
            }
            writer.flush();
            return out.toString();
        } catch (XMLStreamException | RuntimeException e) {
            throw new IOException("Rejected unsafe or malformed XML", e);
        } finally {
            closeQuietly(reader);
            closeQuietly(writer);
        }
    }

    private static void closeQuietly(XMLStreamReader reader) {
        if (reader != null) {
            try {
                reader.close();
            } catch (XMLStreamException ignored) {
                // nothing to do
            }
        }
    }

    private static void closeQuietly(XMLStreamWriter writer) {
        if (writer != null) {
            try {
                writer.close();
            } catch (XMLStreamException ignored) {
                // nothing to do
            }
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
