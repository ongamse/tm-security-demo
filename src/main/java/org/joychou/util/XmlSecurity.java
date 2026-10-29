package org.joychou.util;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.stream.XMLEventReader;
import javax.xml.stream.XMLEventWriter;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLOutputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.XMLEvent;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.StringReader;
import java.io.StringWriter;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

/**
 * Shared hardened XML entry point for untrusted XML.
 *
 * Untrusted XML must pass through {@link #sanitize(String)} (or {@link #sanitizeOoxml}) before it
 * reaches any downstream parser. Those methods reject every DOCTYPE / ENTITY declaration and
 * re-emit the document from a StAX reader that has DTD support and external entities disabled, so the
 * downstream parser only ever receives a DTD-free, entity-free document.
 */
public final class XmlSecurity {

    private XmlSecurity() {
    }

    /**
     * DocumentBuilderFactory with DOCTYPE, external entities, external DTDs, XInclude and
     * external access all disabled.
     */
    public static DocumentBuilderFactory newDocumentBuilderFactory() {
        try {
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
            dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            dbf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
            dbf.setXIncludeAware(false);
            dbf.setExpandEntityReferences(false);
            try {
                dbf.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
                dbf.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
            } catch (IllegalArgumentException ignored) {
                // Non-JAXP-1.5 implementation: the features above already disable external access.
            }
            return dbf;
        } catch (ParserConfigurationException e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * StAX input factory with DTDs and external entities disabled.
     */
    public static XMLInputFactory newXmlInputFactory() {
        XMLInputFactory xif = XMLInputFactory.newInstance();
        xif.setProperty(XMLInputFactory.SUPPORT_DTD, false);
        xif.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
        xif.setProperty(XMLInputFactory.IS_REPLACING_ENTITY_REFERENCES, true);
        try {
            xif.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, "");
            xif.setProperty(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
        } catch (IllegalArgumentException ignored) {
            // Implementation without JAXP 1.5 properties: DTD support is already off.
        }
        return xif;
    }

    /**
     * Rejects DOCTYPE / ENTITY declarations in an untrusted XML string and returns a freshly
     * serialized, DTD-free copy parsed with a hardened StAX reader.
     *
     * @throws IllegalArgumentException if the document declares a DOCTYPE or ENTITY
     * @throws XMLStreamException       if the document is not well-formed
     */
    public static String sanitize(String xml) throws XMLStreamException {
        if (xml == null) {
            throw new IllegalArgumentException("xml is null");
        }
        rejectDeclarations(xml);
        StringWriter out = new StringWriter(xml.length());
        XMLEventReader reader = newXmlInputFactory().createXMLEventReader(new StringReader(xml));
        XMLEventWriter writer = XMLOutputFactory.newInstance().createXMLEventWriter(out);
        try {
            copyEvents(reader, writer);
        } finally {
            writer.close();
            reader.close();
        }
        return out.toString();
    }

    /**
     * Copies an OOXML (zip) package, rewriting every XML part ({@code .xml} / {@code .rels}) through the
     * hardened StAX reader so no DOCTYPE / ENTITY reaches the downstream parser.
     */
    public static void sanitizeOoxml(InputStream in, OutputStream out) throws IOException {
        ZipInputStream zis = new ZipInputStream(in);
        ZipOutputStream zos = new ZipOutputStream(out);
        byte[] buf = new byte[8192];
        ZipEntry entry;
        while ((entry = zis.getNextEntry()) != null) {
            if (entry.isDirectory()) {
                continue;
            }
            String name = entry.getName();
            String lower = name.toLowerCase();
            zos.putNextEntry(new ZipEntry(name));
            if (lower.endsWith(".xml") || lower.endsWith(".rels")) {
                java.io.ByteArrayOutputStream part = new java.io.ByteArrayOutputStream();
                int n;
                while ((n = zis.read(buf)) != -1) {
                    part.write(buf, 0, n);
                }
                byte[] bytes = part.toByteArray();
                rejectDeclarations(new String(bytes, "ISO-8859-1"));
                try {
                    XMLEventReader reader = newXmlInputFactory().createXMLEventReader(new ByteArrayInputStream(bytes));
                    XMLEventWriter writer = XMLOutputFactory.newInstance().createXMLEventWriter(zos, "UTF-8");
                    try {
                        copyEvents(reader, writer);
                    } finally {
                        writer.flush();
                        writer.close();
                        reader.close();
                    }
                } catch (XMLStreamException e) {
                    throw new IllegalArgumentException("invalid XML in " + name, e);
                }
            } else {
                int n;
                while ((n = zis.read(buf)) != -1) {
                    zos.write(buf, 0, n);
                }
            }
            zos.closeEntry();
        }
        zos.finish();
        zos.flush();
    }

    private static void rejectDeclarations(String xml) {
        if (xml.contains("<!DOCTYPE") || xml.contains("<!ENTITY")) {
            throw new IllegalArgumentException("DOCTYPE and ENTITY declarations are not allowed");
        }
    }

    private static void copyEvents(XMLEventReader reader, XMLEventWriter writer) throws XMLStreamException {
        while (reader.hasNext()) {
            XMLEvent event = reader.nextEvent();
            switch (event.getEventType()) {
                case XMLEvent.DTD:
                case XMLEvent.ENTITY_DECLARATION:
                case XMLEvent.NOTATION_DECLARATION:
                case XMLEvent.ENTITY_REFERENCE:
                    throw new IllegalArgumentException("DTD and entity constructs are not allowed");
                case XMLEvent.START_DOCUMENT:
                    // Drop the prolog; the output is re-encoded by the writer.
                    break;
                default:
                    writer.add(event);
            }
        }
    }
}
