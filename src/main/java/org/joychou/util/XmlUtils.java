package org.joychou.util;

import org.apache.commons.digester3.Digester;
import org.jdom2.input.SAXBuilder;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.helpers.DefaultHandler;

import javax.xml.XMLConstants;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;
import java.io.ByteArrayInputStream;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.util.Locale;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/**
 * Shared secure XML helpers. Every untrusted XML parse site should obtain its parser/builder from here
 * and parse only input that went through {@link #sanitizeXml(String)} (or {@link #rejectXmlWithDoctype}).
 */
public final class XmlUtils {

    private static final String DISALLOW_DOCTYPE = "http://apache.org/xml/features/disallow-doctype-decl";
    private static final String EXTERNAL_GENERAL = "http://xml.org/sax/features/external-general-entities";
    private static final String EXTERNAL_PARAMETER = "http://xml.org/sax/features/external-parameter-entities";
    private static final String LOAD_EXTERNAL_DTD = "http://apache.org/xml/features/nonvalidating/load-external-dtd";

    private XmlUtils() {
    }

    /**
     * Secure SAXParserFactory: no DOCTYPE, no external entities, no external DTD, no XInclude.
     */
    public static SAXParserFactory newSecureSaxParserFactory() throws ParserConfigurationException, SAXException {
        SAXParserFactory spf = SAXParserFactory.newInstance();
        spf.setFeature(DISALLOW_DOCTYPE, true);
        spf.setFeature(EXTERNAL_GENERAL, false);
        spf.setFeature(EXTERNAL_PARAMETER, false);
        spf.setFeature(LOAD_EXTERNAL_DTD, false);
        spf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        spf.setXIncludeAware(false);
        return spf;
    }

    /**
     * Secure SAXParser (JAXP access to external DTD/schema denied as well).
     */
    public static SAXParser newSecureSaxParser() throws ParserConfigurationException, SAXException {
        SAXParser parser = newSecureSaxParserFactory().newSAXParser();
        try {
            parser.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, "");
            parser.setProperty(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
        } catch (SAXException ignored) {
            // Parser implementation without JAXP 1.5 properties; the features above still apply.
        }
        return parser;
    }

    /**
     * Validate untrusted XML text with the secure parser and return it for further parsing.
     * Throws if the text is malformed or declares a DOCTYPE / entity.
     */
    public static String sanitizeXml(String xml) throws ParserConfigurationException, SAXException, IOException {
        newSecureSaxParser().parse(new InputSource(new StringReader(xml)), new DefaultHandler());
        return xml;
    }

    /**
     * jdom2 SAXBuilder with DOCTYPE / external entities disabled.
     */
    public static SAXBuilder newSecureSaxBuilder() {
        SAXBuilder builder = new SAXBuilder();
        builder.setFeature(DISALLOW_DOCTYPE, true);
        builder.setFeature(EXTERNAL_GENERAL, false);
        builder.setFeature(EXTERNAL_PARAMETER, false);
        builder.setFeature(LOAD_EXTERNAL_DTD, false);
        builder.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        builder.setExpandEntities(false);
        return builder;
    }

    /**
     * Digester with DOCTYPE / external entities disabled.
     */
    public static Digester newSecureDigester() throws ParserConfigurationException, SAXException {
        // Bind the Digester to an already-hardened SAXParser (DOCTYPE, external entities/DTD, XInclude all
        // disabled, JAXP external access denied) so it can never fall back to its own default factory.
        return new Digester(newSecureSaxParser());
    }

    /**
     * Check every XML part of an xlsx (zip) with the secure parser; any DOCTYPE/entity payload is rejected.
     * Returns the bytes that were checked so callers continue with the very same, sanitised content.
     */
    public static byte[] rejectXmlWithDoctype(byte[] xlsx) throws IOException {
        try (ZipInputStream zis = new ZipInputStream(new ByteArrayInputStream(xlsx))) {
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
                        // no-op
                    }
                };
                try {
                    newSecureSaxParser().parse(new InputSource(part), new DefaultHandler());
                } catch (ParserConfigurationException | SAXException e) {
                    throw new IllegalArgumentException("Rejected xlsx: unsafe or malformed XML part " + entry.getName(), e);
                }
            }
        }
        return xlsx;
    }
}
