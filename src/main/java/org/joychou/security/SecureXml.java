package org.joychou.security;

import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.XMLReader;
import org.xml.sax.helpers.DefaultHandler;
import org.w3c.dom.Document;

import javax.servlet.http.HttpServletRequest;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.parsers.SAXParserFactory;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/**
 * Single entry point for parsing untrusted XML (CWE-611).
 *
 * Every parse here (a) reads the input with a hard size cap, (b) rejects any DOCTYPE / ENTITY
 * declaration by inspecting the raw bytes decoded in every supported charset (UTF-8, UTF-16 and
 * UTF-32 variants) before parsing, and (c) parses with a parser that has DTDs, external entities,
 * XInclude and external DTD/schema access switched off. Callers receive a parsed DOM and read
 * values out of it; the original request text never reaches a parser as a String.
 */
public final class SecureXml {

    private static final String DISALLOW_DOCTYPE = "http://apache.org/xml/features/disallow-doctype-decl";
    private static final String GENERAL_ENTITIES = "http://xml.org/sax/features/external-general-entities";
    private static final String PARAMETER_ENTITIES = "http://xml.org/sax/features/external-parameter-entities";
    private static final String LOAD_EXTERNAL_DTD = "http://apache.org/xml/features/nonvalidating/load-external-dtd";

    /** Hard cap for a request body. */
    public static final int MAX_BODY_BYTES = 1024 * 1024;

    private static final int MAX_XLSX_ENTRIES = 2000;
    private static final long MAX_XLSX_PART_BYTES = 10L * 1024 * 1024;
    private static final long MAX_XLSX_TOTAL_BYTES = 50L * 1024 * 1024;

    private static final List<Charset> DTD_CHECK_CHARSETS = new ArrayList<>();

    static {
        DTD_CHECK_CHARSETS.add(StandardCharsets.UTF_8);
        DTD_CHECK_CHARSETS.add(StandardCharsets.UTF_16);
        DTD_CHECK_CHARSETS.add(StandardCharsets.UTF_16LE);
        DTD_CHECK_CHARSETS.add(StandardCharsets.UTF_16BE);
        for (String name : new String[]{"UTF-32", "UTF-32LE", "UTF-32BE"}) {
            if (Charset.isSupported(name)) {
                DTD_CHECK_CHARSETS.add(Charset.forName(name));
            }
        }
    }

    private SecureXml() {
    }

    /**
     * Read the request body (size capped), reject DOCTYPE / ENTITY, and parse it with the hardened
     * DOM parser.
     *
     * @return the parsed document, or null when the body is empty
     * @throws IllegalArgumentException if the body is too large or carries a DOCTYPE / ENTITY declaration
     */
    public static Document parse(HttpServletRequest request, boolean namespaceAware)
            throws IOException, ParserConfigurationException, SAXException {
        byte[] raw = readCapped(request.getInputStream(), MAX_BODY_BYTES);
        if (raw.length == 0) {
            return null;
        }
        requireNoDtd(raw);
        DocumentBuilder builder = newDocumentBuilderFactory(namespaceAware).newDocumentBuilder();
        builder.setEntityResolver((publicId, systemId) -> new InputSource(new StringReader("")));
        return builder.parse(new InputSource(new ByteArrayInputStream(raw)));
    }

    /**
     * Validate an uploaded OOXML (xlsx) package before a third-party reader opens it: every XML part
     * must be free of DOCTYPE / ENTITY declarations and must be well-formed under the hardened SAX
     * parser. Size, entry-count and total-size caps apply.
     *
     * @throws IllegalArgumentException if the package is unsafe or too large
     */
    public static void requireSafeXlsx(byte[] zipBytes)
            throws IOException, ParserConfigurationException, SAXException {
        SAXParserFactory spf = SAXParserFactory.newInstance();
        spf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        spf.setFeature(DISALLOW_DOCTYPE, true);
        spf.setFeature(GENERAL_ENTITIES, false);
        spf.setFeature(PARAMETER_ENTITIES, false);
        spf.setFeature(LOAD_EXTERNAL_DTD, false);
        spf.setXIncludeAware(false);

        int entries = 0;
        long total = 0;
        try (ZipInputStream zip = new ZipInputStream(new ByteArrayInputStream(zipBytes))) {
            ZipEntry entry;
            while ((entry = zip.getNextEntry()) != null) {
                if (++entries > MAX_XLSX_ENTRIES) {
                    throw new IllegalArgumentException("Too many entries");
                }
                String name = entry.getName().toLowerCase(Locale.ROOT);
                if (entry.isDirectory() || !(name.endsWith(".xml") || name.endsWith(".rels"))) {
                    continue;
                }
                byte[] part = readCapped(zip, MAX_XLSX_PART_BYTES);
                total += part.length;
                if (total > MAX_XLSX_TOTAL_BYTES) {
                    throw new IllegalArgumentException("Package too large");
                }
                requireNoDtd(part);
                XMLReader reader = spf.newSAXParser().getXMLReader();
                reader.setEntityResolver((publicId, systemId) -> new InputSource(new StringReader("")));
                reader.setContentHandler(new DefaultHandler());
                reader.parse(new InputSource(new ByteArrayInputStream(part)));
            }
        }
    }

    /** Read at most {@code max} bytes; fail closed when the stream is longer. */
    public static byte[] readCapped(InputStream in, long max) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        long total = 0;
        int n;
        while ((n = in.read(buf)) != -1) {
            total += n;
            if (total > max) {
                throw new IllegalArgumentException("XML input too large");
            }
            out.write(buf, 0, n);
        }
        return out.toByteArray();
    }

    private static void requireNoDtd(byte[] data) {
        for (Charset cs : DTD_CHECK_CHARSETS) {
            String text = new String(data, cs).replace("\0", "").toUpperCase(Locale.ROOT);
            if (text.contains("<!DOCTYPE") || text.contains("<!ENTITY")) {
                throw new IllegalArgumentException("DOCTYPE and ENTITY declarations are not allowed");
            }
        }
    }

    private static DocumentBuilderFactory newDocumentBuilderFactory(boolean namespaceAware)
            throws ParserConfigurationException {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(namespaceAware);
        dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        dbf.setFeature(DISALLOW_DOCTYPE, true);
        dbf.setFeature(GENERAL_ENTITIES, false);
        dbf.setFeature(PARAMETER_ENTITIES, false);
        dbf.setFeature(LOAD_EXTERNAL_DTD, false);
        dbf.setXIncludeAware(false);
        dbf.setExpandEntityReferences(false);
        dbf.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        dbf.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
        return dbf;
    }
}
