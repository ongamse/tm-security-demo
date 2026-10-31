package org.joychou.util;

import com.thoughtworks.xstream.XStream;
import com.thoughtworks.xstream.io.xml.DomDriver;
import com.thoughtworks.xstream.io.xml.DomReader;
import com.thoughtworks.xstream.security.NoTypePermission;
import com.thoughtworks.xstream.security.NullPermission;
import com.thoughtworks.xstream.security.PrimitiveTypePermission;
import org.apache.commons.digester3.Digester;
import org.jdom2.JDOMException;
import org.jdom2.input.DOMBuilder;
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

    private static class DenyingHandler extends DefaultHandler {
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

    // ------------------------------------------------------------------ parsing

    /**
     * Parses request-derived XML with a JDOM2 builder fed from the hardened DOM parse.
     */
    public static org.jdom2.Document buildJdom(String xml)
            throws JDOMException, IOException, SAXException {
        try {
            return new DOMBuilder().build(parseHardenedDom(xml));
        } catch (ParserConfigurationException e) {
            throw new SAXException(e);
        }
    }

    /**
     * Parses request-derived XML with a Commons Digester that is driven as the content handler of
     * a hardened SAX parser.
     */
    public static Object parseDigester(String xml)
            throws IOException, SAXException, ParserConfigurationException {
        requireNoDtd(xml);

        SAXParserFactory spf = SAXParserFactory.newInstance();
        spf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        spf.setFeature(DISALLOW_DOCTYPE, true);
        spf.setFeature(GENERAL_ENTITIES, false);
        spf.setFeature(PARAMETER_ENTITIES, false);
        spf.setFeature(LOAD_EXTERNAL_DTD, false);
        spf.setXIncludeAware(false);
        spf.setNamespaceAware(true);
        SAXParser parser = spf.newSAXParser();
        try {
            parser.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, "");
            parser.setProperty(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
        } catch (SAXException ignored) {
            // property unsupported by this parser implementation; DOCTYPE is already disallowed
        }

        Digester digester = new Digester();
        digester.setEntityResolver(DENY_ENTITIES);
        parser.parse(new InputSource(new StringReader(xml)), digester);
        return digester.getRoot();
    }

    /** Parses request-derived XML into a DOM with a hardened DocumentBuilder. */
    public static Document parseDom(String xml)
            throws IOException, SAXException, ParserConfigurationException {
        return parseHardenedDom(xml);
    }

    /** OWASP-style hardened DOM parse: factory, hardening and parse all live in this method. */
    private static Document parseHardenedDom(String xml)
            throws IOException, SAXException, ParserConfigurationException {
        requireNoDtd(xml);

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
            // attribute unsupported by this parser implementation; DOCTYPE is already disallowed
        }
        DocumentBuilder db = dbf.newDocumentBuilder();
        db.setEntityResolver(DENY_ENTITIES);
        return db.parse(new InputSource(new StringReader(xml)));
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
        Document document = parseHardenedDom(xml);
        return xstream.unmarshal(new DomReader(document));
    }

    // --------------------------------------------------------------------- xlsx

    private static final int MAX_ZIP_ENTRIES = 1000;
    private static final long MAX_ENTRY_BYTES = 10L * 1024 * 1024;
    private static final long MAX_TOTAL_BYTES = 100L * 1024 * 1024;

    /** Stream view of one zip entry that fails once more than the allowed bytes are read. */
    private static final class BoundedEntryStream extends FilterInputStream {
        private final long limit;
        private final long[] total;
        private long read;

        BoundedEntryStream(InputStream in, long limit, long[] total) {
            super(in);
            this.limit = limit;
            this.total = total;
        }

        private void count(long n) throws IOException {
            if (n > 0) {
                read += n;
                total[0] += n;
                if (read > limit || total[0] > MAX_TOTAL_BYTES) {
                    throw new IOException("xlsx part exceeds the allowed size");
                }
            }
        }

        @Override
        public int read() throws IOException {
            int b = super.read();
            if (b >= 0) {
                count(1);
            }
            return b;
        }

        @Override
        public int read(byte[] buf, int off, int len) throws IOException {
            int n = super.read(buf, off, len);
            count(n);
            return n;
        }

        @Override
        public void close() {
            // keep the underlying ZipInputStream open
        }
    }

    /**
     * Parses every XML part of an OOXML (zip) package with a hardened SAX parser; throws if the
     * package has too many entries, any entry is larger than 10 MB, any part declares a
     * DOCTYPE/ENTITY, or any part is not well-formed.
     */
    public static void requireSafeXlsx(byte[] content) throws IOException {
        summarizeXlsx(content);
    }

    /** Counts rows and cells while streaming worksheet XML through the hardened SAX parser. */
    private static final class SheetCounter extends DenyingHandler {
        private final long[] counts;

        SheetCounter(long[] counts) {
            this.counts = counts;
        }

        @Override
        public void startElement(String uri, String localName, String qName,
                                 org.xml.sax.Attributes attributes) {
            String name = qName == null ? "" : qName;
            int colon = name.indexOf(':');
            if (colon >= 0) {
                name = name.substring(colon + 1);
            }
            if ("row".equals(name)) {
                counts[0]++;
            } else if ("c".equals(name)) {
                counts[1]++;
            }
        }
    }

    /**
     * Validates the package exactly like {@link #requireSafeXlsx(byte[])} and, in the same single
     * pass of the hardened SAX parser, reads the worksheet parts (xl/worksheets/*.xml).
     *
     * @return {rowCount, cellCount} across all worksheets
     */
    public static long[] summarizeXlsx(byte[] content) throws IOException {
        long[] sheetCounts = new long[2];
        try {
            SAXParserFactory spf = SAXParserFactory.newInstance();
            spf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            spf.setFeature(DISALLOW_DOCTYPE, true);
            spf.setFeature(GENERAL_ENTITIES, false);
            spf.setFeature(PARAMETER_ENTITIES, false);
            spf.setFeature(LOAD_EXTERNAL_DTD, false);
            spf.setXIncludeAware(false);

            long[] total = new long[1];
            int entries = 0;
            try (ZipInputStream zis = new ZipInputStream(new ByteArrayInputStream(content))) {
                ZipEntry entry;
                while ((entry = zis.getNextEntry()) != null) {
                    if (++entries > MAX_ZIP_ENTRIES) {
                        throw new IOException("xlsx package has too many entries");
                    }
                    if (entry.getSize() > MAX_ENTRY_BYTES) {
                        throw new IOException("xlsx entry exceeds the allowed size");
                    }
                    String name = entry.getName().toLowerCase(Locale.ROOT);
                    if (entry.isDirectory() || !(name.endsWith(".xml") || name.endsWith(".rels"))) {
                        // Still bound what is inflated for entries that are skipped.
                        drain(new BoundedEntryStream(zis, MAX_ENTRY_BYTES, total));
                        continue;
                    }
                    SAXParser parser = spf.newSAXParser();
                    try {
                        parser.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, "");
                        parser.setProperty(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
                    } catch (SAXException ignored) {
                        // property unsupported by this parser implementation; DOCTYPE is disallowed
                    }
                    DefaultHandler handler = (name.startsWith("xl/worksheets/") && name.endsWith(".xml"))
                            ? new SheetCounter(sheetCounts) : new DenyingHandler();
                    parser.parse(new BoundedEntryStream(zis, MAX_ENTRY_BYTES, total), handler);
                }
            }
            return sheetCounts;
        } catch (IOException e) {
            throw e;
        } catch (Exception e) {
            throw new IOException("Invalid or unsafe xlsx XML content", e);
        }
    }

    private static void drain(InputStream in) throws IOException {
        byte[] buf = new byte[8192];
        while (in.read(buf) != -1) {
            // discard, size is enforced by the bounded stream
        }
    }
}
