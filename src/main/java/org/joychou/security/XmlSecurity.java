package org.joychou.security;

import org.jdom2.input.SAXBuilder;
import org.jdom2.input.sax.XMLReaders;
import org.apache.commons.digester3.Digester;
import org.xml.sax.InputSource;
import org.xml.sax.XMLReader;
import org.xml.sax.helpers.DefaultHandler;

import javax.servlet.http.HttpServletRequest;
import javax.xml.XMLConstants;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

/**
 * Shared hardened XML parsing helpers. Every parser returned here has DOCTYPE declarations,
 * external entities, external DTDs, XInclude and external schema/stylesheet access disabled
 * before it is handed to the caller. If any control cannot be applied the helper throws
 * (fail closed) instead of returning a weaker parser.
 */
public final class XmlSecurity {

    /** Maximum accepted request body size in bytes. */
    public static final int MAX_BODY_BYTES = 1024 * 1024;

    private static final String FEATURE_DISALLOW_DOCTYPE = "http://apache.org/xml/features/disallow-doctype-decl";
    private static final String FEATURE_EXTERNAL_GENERAL = "http://xml.org/sax/features/external-general-entities";
    private static final String FEATURE_EXTERNAL_PARAMETER = "http://xml.org/sax/features/external-parameter-entities";
    private static final String FEATURE_LOAD_EXTERNAL_DTD = "http://apache.org/xml/features/nonvalidating/load-external-dtd";

    private XmlSecurity() {
    }

    /**
     * Read the request body with a hard size cap. Throws IOException when the body is larger
     * than {@link #MAX_BODY_BYTES}.
     */
    public static String readBody(HttpServletRequest request) throws IOException {
        if (request.getContentLength() > MAX_BODY_BYTES) {
            throw new IOException("request body too large");
        }
        Charset charset = StandardCharsets.UTF_8;
        String enc = request.getCharacterEncoding();
        if (enc != null) {
            try {
                charset = Charset.forName(enc);
            } catch (RuntimeException ignored) {
                charset = StandardCharsets.UTF_8;
            }
        }
        try (InputStream in = request.getInputStream()) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buf = new byte[8192];
            int total = 0;
            int n;
            while ((n = in.read(buf)) != -1) {
                total += n;
                if (total > MAX_BODY_BYTES) {
                    throw new IOException("request body too large");
                }
                out.write(buf, 0, n);
            }
            return new String(out.toByteArray(), charset);
        }
    }

    /** SAXParserFactory with DTDs, external entities and XInclude disabled. */
    public static SAXParserFactory newSaxParserFactory() {
        try {
            SAXParserFactory spf = SAXParserFactory.newInstance();
            spf.setNamespaceAware(true);
            spf.setValidating(false);
            spf.setXIncludeAware(false);
            spf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            spf.setFeature(FEATURE_DISALLOW_DOCTYPE, true);
            spf.setFeature(FEATURE_EXTERNAL_GENERAL, false);
            spf.setFeature(FEATURE_EXTERNAL_PARAMETER, false);
            spf.setFeature(FEATURE_LOAD_EXTERNAL_DTD, false);
            return spf;
        } catch (Exception e) {
            throw new IllegalStateException("unable to harden SAXParserFactory", e);
        }
    }

    /** XMLReader with DTDs, external entities and external DTD/schema access disabled. */
    public static XMLReader newXMLReader() {
        try {
            SAXParser parser = newSaxParserFactory().newSAXParser();
            parser.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, "");
            parser.setProperty(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
            XMLReader reader = parser.getXMLReader();
            reader.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            reader.setFeature(FEATURE_DISALLOW_DOCTYPE, true);
            reader.setFeature(FEATURE_EXTERNAL_GENERAL, false);
            reader.setFeature(FEATURE_EXTERNAL_PARAMETER, false);
            reader.setFeature(FEATURE_LOAD_EXTERNAL_DTD, false);
            reader.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, "");
            reader.setProperty(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
            reader.setEntityResolver((publicId, systemId) -> new InputSource(new StringReader("")));
            return reader;
        } catch (Exception e) {
            throw new IllegalStateException("unable to harden XMLReader", e);
        }
    }

    /** JDOM SAXBuilder backed by a hardened non-validating reader. */
    public static SAXBuilder newSAXBuilder() {
        try {
            SAXBuilder builder = new SAXBuilder(XMLReaders.NONVALIDATING);
            builder.setExpandEntities(false);
            builder.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            builder.setFeature(FEATURE_DISALLOW_DOCTYPE, true);
            builder.setFeature(FEATURE_EXTERNAL_GENERAL, false);
            builder.setFeature(FEATURE_EXTERNAL_PARAMETER, false);
            builder.setFeature(FEATURE_LOAD_EXTERNAL_DTD, false);
            builder.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, "");
            builder.setProperty(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
            builder.setEntityResolver((publicId, systemId) -> new InputSource(new StringReader("")));
            return builder;
        } catch (RuntimeException e) {
            throw new IllegalStateException("unable to harden SAXBuilder", e);
        }
    }

    /** Commons Digester that parses through a hardened XMLReader. */
    public static Digester newDigester() {
        return new Digester(newXMLReader());
    }

    /**
     * Parse the document with the hardened reader and discard the events. Throws if the
     * document is not well formed or declares a DOCTYPE / external entity.
     */
    public static void requireSafeXml(String xml) throws Exception {
        newXMLReader().parse(new InputSource(new StringReader(xml)));
    }

    /** Same as {@link #requireSafeXml(String)} for raw bytes (encoding detected by the parser). */
    public static void requireSafeXml(byte[] xml) throws Exception {
        XMLReader reader = newXMLReader();
        reader.setContentHandler(new DefaultHandler());
        reader.parse(new InputSource(new ByteArrayInputStream(xml)));
    }
}
