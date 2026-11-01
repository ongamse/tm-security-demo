package org.joychou.security;

import org.dom4j.io.SAXReader;
import org.apache.commons.digester3.Digester;
import org.jdom2.input.SAXBuilder;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.xml.sax.EntityResolver;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.XMLReader;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.util.Locale;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/**
 * Single place that builds hardened XML parsers and validates untrusted XML payloads.
 * <p>
 * Every parser returned here has DOCTYPE declarations disabled, external general/parameter entities
 * disabled, external DTD loading disabled, XInclude disabled, entity reference expansion disabled,
 * secure processing enabled and an entity resolver that never resolves anything.
 * Untrusted payloads must be read through {@link #readValidated(InputStream)} (or checked with
 * {@link #requireNoDtd(byte[])}) before they are handed to any parser.
 */
public final class XmlSafe {

    public static final int MAX_XML_BYTES = 1024 * 1024;

    private static final int MAX_UPLOAD_BYTES = 20 * 1024 * 1024;
    private static final int MAX_ZIP_ENTRIES = 2000;
    private static final int MAX_XML_PART_BYTES = 10 * 1024 * 1024;
    private static final long MAX_XML_PARTS_TOTAL = 50L * 1024 * 1024;

    private static final String DISALLOW_DOCTYPE = "http://apache.org/xml/features/disallow-doctype-decl";
    private static final String EXT_GENERAL = "http://xml.org/sax/features/external-general-entities";
    private static final String EXT_PARAMETER = "http://xml.org/sax/features/external-parameter-entities";
    private static final String LOAD_EXT_DTD = "http://apache.org/xml/features/nonvalidating/load-external-dtd";

    /** Resolver that never loads anything external. */
    private static final EntityResolver EMPTY_RESOLVER = (publicId, systemId) -> new InputSource(new StringReader(""));

    private XmlSafe() {
    }

    /**
     * Thrown for rejected XML. Maps to HTTP 400 and carries no message, so nothing from the
     * request or from the parser is echoed back.
     */
    @ResponseStatus(value = HttpStatus.BAD_REQUEST, reason = "invalid xml")
    public static class RejectedXmlException extends RuntimeException {
        private static final long serialVersionUID = 1L;

        public RejectedXmlException() {
            super(null, null, false, false);
        }
    }

    // ------------------------------------------------------------------ payload validation

    /**
     * Read at most {@link #MAX_XML_BYTES} from the stream and reject any DOCTYPE / ENTITY declaration.
     */
    public static byte[] readValidated(InputStream in) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buf = new byte[4096];
        int n;
        while ((n = in.read(buf)) != -1) {
            out.write(buf, 0, n);
            if (out.size() > MAX_XML_BYTES) {
                throw new RejectedXmlException();
            }
        }
        return requireNoDtd(out.toByteArray());
    }

    /**
     * Reject empty payloads and payloads carrying a DOCTYPE or ENTITY declaration.
     * NUL bytes are ignored so UTF-16/UTF-32 encoded payloads are covered as well.
     */
    public static byte[] requireNoDtd(byte[] xml) {
        if (xml == null || xml.length == 0 || containsDtd(xml)) {
            throw new RejectedXmlException();
        }
        return xml;
    }

    private static boolean containsDtd(byte[] data) {
        StringBuilder sb = new StringBuilder(data.length);
        for (byte b : data) {
            if (b != 0) {
                sb.append((char) (b & 0xFF));
            }
        }
        String s = sb.toString().toLowerCase(Locale.ROOT);
        return s.contains("<!doctype") || s.contains("<!entity");
    }

    public static InputSource toInputSource(byte[] validatedXml) {
        return new InputSource(new ByteArrayInputStream(validatedXml));
    }

    /**
     * Validate an untrusted OOXML (xlsx) upload: size cap, ZIP magic, bounded entry count / size and
     * no DOCTYPE / ENTITY in any XML part. Returns the validated bytes.
     */
    public static byte[] validateOoxmlUpload(InputStream in) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        int n;
        while ((n = in.read(buf)) != -1) {
            out.write(buf, 0, n);
            if (out.size() > MAX_UPLOAD_BYTES) {
                throw new RejectedXmlException();
            }
        }
        byte[] data = out.toByteArray();
        if (data.length < 4 || data[0] != 'P' || data[1] != 'K' || data[2] != 3 || data[3] != 4) {
            throw new RejectedXmlException();
        }

        int entries = 0;
        long total = 0;
        try (ZipInputStream zis = new ZipInputStream(new ByteArrayInputStream(data))) {
            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                if (++entries > MAX_ZIP_ENTRIES) {
                    throw new RejectedXmlException();
                }
                String name = entry.getName().toLowerCase(Locale.ROOT);
                if (entry.isDirectory()
                        || !(name.endsWith(".xml") || name.endsWith(".rels") || name.endsWith(".vml"))) {
                    continue;
                }
                ByteArrayOutputStream part = new ByteArrayOutputStream();
                int r;
                while ((r = zis.read(buf)) != -1) {
                    part.write(buf, 0, r);
                    total += r;
                    if (part.size() > MAX_XML_PART_BYTES || total > MAX_XML_PARTS_TOTAL) {
                        throw new RejectedXmlException();
                    }
                }
                if (containsDtd(part.toByteArray())) {
                    throw new RejectedXmlException();
                }
            }
        }
        return data;
    }

    // ------------------------------------------------------------------ hardened factories

    private static void strict(XMLReader reader) throws SAXException {
        reader.setFeature(DISALLOW_DOCTYPE, true);
        reader.setFeature(EXT_GENERAL, false);
        reader.setFeature(EXT_PARAMETER, false);
        reader.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        try {
            reader.setFeature(LOAD_EXT_DTD, false);
        } catch (SAXException ignored) {
            // not supported by this parser; DOCTYPE is already disallowed
        }
        reader.setEntityResolver(EMPTY_RESOLVER);
    }

    public static DocumentBuilderFactory newDocumentBuilderFactory() throws ParserConfigurationException {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setFeature(DISALLOW_DOCTYPE, true);
        dbf.setFeature(EXT_GENERAL, false);
        dbf.setFeature(EXT_PARAMETER, false);
        dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        try {
            dbf.setFeature(LOAD_EXT_DTD, false);
        } catch (ParserConfigurationException ignored) {
            // not supported by this parser
        }
        dbf.setXIncludeAware(false);
        dbf.setExpandEntityReferences(false);
        dbf.setNamespaceAware(true);
        try {
            dbf.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
            dbf.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
        } catch (IllegalArgumentException ignored) {
            // JAXP implementation without these attributes
        }
        return dbf;
    }

    public static DocumentBuilder newDocumentBuilder() throws ParserConfigurationException {
        DocumentBuilder db = newDocumentBuilderFactory().newDocumentBuilder();
        db.setEntityResolver(EMPTY_RESOLVER);
        return db;
    }

    /**
     * Parse an already validated payload into a DOM. Any failure maps to {@link RejectedXmlException}
     * so no parser message reaches the client.
     */
    public static org.w3c.dom.Document parseDocument(byte[] validatedXml) {
        try {
            return newDocumentBuilder().parse(toInputSource(validatedXml));
        } catch (Exception e) {
            throw new RejectedXmlException();
        }
    }

    public static SAXParserFactory newSAXParserFactory() throws ParserConfigurationException, SAXException {
        SAXParserFactory spf = SAXParserFactory.newInstance();
        spf.setFeature(DISALLOW_DOCTYPE, true);
        spf.setFeature(EXT_GENERAL, false);
        spf.setFeature(EXT_PARAMETER, false);
        spf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        try {
            spf.setFeature(LOAD_EXT_DTD, false);
        } catch (ParserConfigurationException | SAXException ignored) {
            // not supported by this parser
        }
        spf.setXIncludeAware(false);
        spf.setNamespaceAware(true);
        return spf;
    }

    public static SAXParser newSAXParser() throws ParserConfigurationException, SAXException {
        SAXParser parser = newSAXParserFactory().newSAXParser();
        try {
            parser.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, "");
            parser.setProperty(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
        } catch (SAXException ignored) {
            // JAXP implementation without these properties
        }
        strict(parser.getXMLReader());
        return parser;
    }

    public static XMLReader newXMLReader() throws ParserConfigurationException, SAXException {
        XMLReader reader = newSAXParser().getXMLReader();
        strict(reader);
        return reader;
    }

    /** dom4j reader on top of a hardened XMLReader. */
    public static SAXReader newSAXReader() throws ParserConfigurationException, SAXException {
        SAXReader reader = new SAXReader(newXMLReader());
        reader.setFeature(DISALLOW_DOCTYPE, true);
        reader.setFeature(EXT_GENERAL, false);
        reader.setFeature(EXT_PARAMETER, false);
        reader.setIncludeExternalDTDDeclarations(false);
        reader.setIncludeInternalDTDDeclarations(false);
        reader.setEntityResolver(EMPTY_RESOLVER);
        return reader;
    }

    /** JDOM2 builder with hardened features. */
    public static SAXBuilder newSAXBuilder() {
        SAXBuilder builder = new SAXBuilder();
        builder.setFeature(DISALLOW_DOCTYPE, true);
        builder.setFeature(EXT_GENERAL, false);
        builder.setFeature(EXT_PARAMETER, false);
        builder.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        builder.setExpandEntities(false);
        builder.setEntityResolver(EMPTY_RESOLVER);
        return builder;
    }

    /** Commons Digester on top of a hardened XMLReader. */
    public static Digester newDigester() throws ParserConfigurationException, SAXException {
        return new Digester(newXMLReader());
    }
}
