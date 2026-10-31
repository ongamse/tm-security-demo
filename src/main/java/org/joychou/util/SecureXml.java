package org.joychou.util;

import com.thoughtworks.xstream.XStream;
import com.thoughtworks.xstream.io.xml.DomDriver;
import com.thoughtworks.xstream.io.xml.DomReader;
import com.thoughtworks.xstream.security.NoTypePermission;
import com.thoughtworks.xstream.security.NullPermission;
import com.thoughtworks.xstream.security.PrimitiveTypePermission;
import org.apache.commons.digester3.Digester;
import org.jdom2.JDOMException;
import org.jdom2.input.SAXBuilder;
import org.w3c.dom.Document;
import org.xml.sax.EntityResolver;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.helpers.DefaultHandler;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;
import java.io.ByteArrayInputStream;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.util.Locale;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/**
 * Single place that builds hardened XML parsers and parses request-derived XML.
 *
 * Every parser created here has: secure processing on, DOCTYPE disallowed, external general and
 * parameter entities off, external DTD loading off, XInclude off, and (where the parser supports
 * it) ACCESS_EXTERNAL_DTD / ACCESS_EXTERNAL_SCHEMA set to "". In addition every request body is
 * rejected up front when it contains a DOCTYPE or ENTITY declaration.
 */
public final class SecureXml {

    private static final String DISALLOW_DOCTYPE = "http://apache.org/xml/features/disallow-doctype-decl";
    private static final String GENERAL_ENTITIES = "http://xml.org/sax/features/external-general-entities";
    private static final String PARAMETER_ENTITIES = "http://xml.org/sax/features/external-parameter-entities";
    private static final String LOAD_EXTERNAL_DTD = "http://apache.org/xml/features/nonvalidating/load-external-dtd";

    private static final Pattern FORBIDDEN_DECLARATION =
            Pattern.compile("<!(DOCTYPE|ENTITY)", Pattern.CASE_INSENSITIVE);

    /** Refuses to resolve any external entity or DTD. */
    private static final EntityResolver DENY_ENTITIES = (publicId, systemId) -> {
        throw new SAXException("External entities are not allowed");
    };

    private static final class DenyingHandler extends DefaultHandler {
        @Override
        public InputSource resolveEntity(String publicId, String systemId) throws SAXException {
            throw new SAXException("External entities are not allowed");
        }
    }

    private SecureXml() {
    }

    /**
     * Rejects XML text containing a DOCTYPE or ENTITY declaration (case-insensitive).
     *
     * @return the same text when it is acceptable
     */
    public static String requireNoDtd(String xml) throws SAXException {
        if (xml != null && FORBIDDEN_DECLARATION.matcher(xml).find()) {
            throw new SAXException("DOCTYPE and ENTITY declarations are not allowed");
        }
        return xml;
    }

    // ---------------------------------------------------------------- factories

    public static SAXParserFactory newSaxParserFactory() throws ParserConfigurationException, SAXException {
        SAXParserFactory spf = SAXParserFactory.newInstance();
        spf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        spf.setFeature(DISALLOW_DOCTYPE, true);
        spf.setFeature(GENERAL_ENTITIES, false);
        spf.setFeature(PARAMETER_ENTITIES, false);
        spf.setFeature(LOAD_EXTERNAL_DTD, false);
        spf.setXIncludeAware(false);
        return spf;
    }

    public static SAXParser newSaxParser() throws ParserConfigurationException, SAXException {
        SAXParser parser = newSaxParserFactory().newSAXParser();
        // Not every parser implementation knows these; DOCTYPE is already disallowed above.
        trySetProperty(parser, XMLConstants.ACCESS_EXTERNAL_DTD);
        trySetProperty(parser, XMLConstants.ACCESS_EXTERNAL_SCHEMA);
        return parser;
    }

    public static DocumentBuilder newDocumentBuilder() throws ParserConfigurationException {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        dbf.setFeature(DISALLOW_DOCTYPE, true);
        dbf.setFeature(GENERAL_ENTITIES, false);
        dbf.setFeature(PARAMETER_ENTITIES, false);
        dbf.setFeature(LOAD_EXTERNAL_DTD, false);
        dbf.setXIncludeAware(false);
        dbf.setExpandEntityReferences(false);
        trySetAttribute(dbf, XMLConstants.ACCESS_EXTERNAL_DTD);
        trySetAttribute(dbf, XMLConstants.ACCESS_EXTERNAL_SCHEMA);
        DocumentBuilder db = dbf.newDocumentBuilder();
        db.setEntityResolver(DENY_ENTITIES);
        return db;
    }

    public static SAXBuilder newSaxBuilder() {
        SAXBuilder builder = new SAXBuilder();
        builder.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        builder.setFeature(DISALLOW_DOCTYPE, true);
        builder.setFeature(GENERAL_ENTITIES, false);
        builder.setFeature(PARAMETER_ENTITIES, false);
        builder.setFeature(LOAD_EXTERNAL_DTD, false);
        builder.setExpandEntities(false);
        builder.setEntityResolver(DENY_ENTITIES);
        return builder;
    }

    public static org.dom4j.io.SAXReader newSaxReader() throws SAXException {
        org.dom4j.io.SAXReader reader = new org.dom4j.io.SAXReader();
        reader.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        reader.setFeature(DISALLOW_DOCTYPE, true);
        reader.setFeature(GENERAL_ENTITIES, false);
        reader.setFeature(PARAMETER_ENTITIES, false);
        reader.setFeature(LOAD_EXTERNAL_DTD, false);
        reader.setEntityResolver(DENY_ENTITIES);
        return reader;
    }

    /** Parses request-derived XML with a hardened dom4j SAXReader. */
    public static org.dom4j.Document parseDom4j(String xml) throws org.dom4j.DocumentException, SAXException {
        requireNoDtd(xml);
        return newSaxReader().read(new InputSource(new StringReader(xml)));
    }

    public static Digester newDigester() throws ParserConfigurationException, SAXException {
        Digester digester = new Digester();
        digester.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        digester.setFeature(DISALLOW_DOCTYPE, true);
        digester.setFeature(GENERAL_ENTITIES, false);
        digester.setFeature(PARAMETER_ENTITIES, false);
        digester.setFeature(LOAD_EXTERNAL_DTD, false);
        digester.setEntityResolver(DENY_ENTITIES);
        return digester;
    }

    // ------------------------------------------------------------------ parsing

    /** Parses request-derived XML with a hardened JDOM2 SAXBuilder. */
    public static org.jdom2.Document buildJdom(String xml) throws JDOMException, IOException, SAXException {
        requireNoDtd(xml);
        return newSaxBuilder().build(new InputSource(new StringReader(xml)));
    }

    /** Parses request-derived XML with a hardened Commons Digester. */
    public static Object parseDigester(String xml)
            throws IOException, SAXException, ParserConfigurationException {
        requireNoDtd(xml);
        return newDigester().parse(new StringReader(xml));
    }

    /** Parses request-derived XML into a DOM with a hardened DocumentBuilder. */
    public static Document parseDom(String xml)
            throws IOException, SAXException, ParserConfigurationException {
        requireNoDtd(xml);
        return newDocumentBuilder().parse(new InputSource(new StringReader(xml)));
    }

    // ------------------------------------------------------------------- XStream

    /**
     * XStream that denies every type except null, primitives, and the given allowlist, with
     * annotation processing off.
     */
    public static XStream newAllowlistedXStream(Class<?>... allowed) {
        XStream xstream = new XStream(new DomDriver());
        xstream.autodetectAnnotations(false);
        xstream.addPermission(NoTypePermission.NONE);
        xstream.addPermission(NullPermission.NULL);
        xstream.addPermission(PrimitiveTypePermission.PRIMITIVES);
        xstream.allowTypes(allowed);
        return xstream;
    }

    /**
     * Deserializes request-derived XML. The text is first rejected if it declares a DOCTYPE or
     * ENTITY and is parsed with the hardened DocumentBuilder, then handed to XStream as a DOM so
     * XStream's own (non-hardened) parser never sees the raw input.
     */
    public static Object fromXml(XStream xstream, String xml)
            throws IOException, SAXException, ParserConfigurationException {
        Document document = parseDom(xml);
        return xstream.unmarshal(new DomReader(document));
    }

    // --------------------------------------------------------------------- xlsx

    /**
     * Parses every XML part of an OOXML (zip) package with the hardened SAX parser; throws if any
     * part declares a DOCTYPE/ENTITY or is not well-formed.
     */
    public static void requireSafeXlsx(byte[] content) throws IOException {
        try {
            try (ZipInputStream zis = new ZipInputStream(new ByteArrayInputStream(content))) {
                ZipEntry entry;
                while ((entry = zis.getNextEntry()) != null) {
                    String name = entry.getName().toLowerCase(Locale.ROOT);
                    if (entry.isDirectory() || !(name.endsWith(".xml") || name.endsWith(".rels"))) {
                        continue;
                    }
                    // Do not let the parser close the shared zip stream.
                    InputStream part = new FilterInputStream(zis) {
                        @Override
                        public void close() {
                            // keep the underlying ZipInputStream open
                        }
                    };
                    newSaxParser().parse(part, new DenyingHandler());
                }
            }
        } catch (IOException e) {
            throw e;
        } catch (Exception e) {
            throw new IOException("Invalid or unsafe xlsx XML content", e);
        }
    }

    // ------------------------------------------------------------------ helpers

    private static void trySetProperty(SAXParser parser, String property) {
        try {
            parser.setProperty(property, "");
        } catch (SAXException ignored) {
            // property unsupported by this parser implementation
        }
    }

    private static void trySetAttribute(DocumentBuilderFactory dbf, String attribute) {
        try {
            dbf.setAttribute(attribute, "");
        } catch (IllegalArgumentException ignored) {
            // attribute unsupported by this parser implementation
        }
    }
}
