package org.joychou.util;

import org.apache.commons.digester3.Digester;
import org.jdom2.Document;
import org.jdom2.JDOMException;
import org.jdom2.input.SAXBuilder;
import org.jdom2.input.sax.XMLReaderJDOMFactory;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.xml.sax.EntityResolver;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.XMLReader;

import javax.servlet.http.HttpServletRequest;
import javax.xml.XMLConstants;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.regex.Pattern;

/**
 * Shared, per-call hardened XML parsing helpers.
 *
 * Every parser built here has secure processing on, DOCTYPE declarations disallowed, external
 * general/parameter entities and external DTDs off, XInclude off, and an entity resolver that
 * always returns an empty source. ACCESS_EXTERNAL_* restrictions are set on the parser instance,
 * never through JVM-wide System properties. Request bodies are size capped and rejected up front
 * when they contain a DOCTYPE or ENTITY declaration.
 */
public final class SecureXml {

    /** Maximum accepted XML request body size in bytes. */
    public static final int MAX_BODY_BYTES = 1024 * 1024;

    private static final String DISALLOW_DOCTYPE = "http://apache.org/xml/features/disallow-doctype-decl";
    private static final String EXTERNAL_GENERAL = "http://xml.org/sax/features/external-general-entities";
    private static final String EXTERNAL_PARAMETER = "http://xml.org/sax/features/external-parameter-entities";
    private static final String LOAD_EXTERNAL_DTD = "http://apache.org/xml/features/nonvalidating/load-external-dtd";
    private static final String XINCLUDE = "http://apache.org/xml/features/xinclude";

    private static final Pattern DTD_DECLARATION =
            Pattern.compile("<!\\s*(?:DOCTYPE|ENTITY)", Pattern.CASE_INSENSITIVE);

    private static final EntityResolver EMPTY_RESOLVER = (publicId, systemId) -> new InputSource(new StringReader(""));

    private SecureXml() {
    }

    /** Thrown when XML input is refused before parsing; mapped to HTTP 400. */
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public static class XmlRejectedException extends RuntimeException {
        private static final long serialVersionUID = 1L;

        public XmlRejectedException(String message) {
            super(message);
        }

        public XmlRejectedException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    /**
     * Read the request body with a size cap and reject DOCTYPE / ENTITY declarations.
     */
    public static String readBody(HttpServletRequest request) throws IOException {
        InputStream in = request.getInputStream();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buf = new byte[4096];
        int total = 0;
        int n;
        while ((n = in.read(buf)) != -1) {
            total += n;
            if (total > MAX_BODY_BYTES) {
                throw new XmlRejectedException("XML body too large");
            }
            out.write(buf, 0, n);
        }
        Charset charset = StandardCharsets.UTF_8;
        String encoding = request.getCharacterEncoding();
        if (encoding != null) {
            try {
                charset = Charset.forName(encoding);
            } catch (IllegalArgumentException e) {
                charset = StandardCharsets.UTF_8;
            }
        }
        return requireSafeBody(new String(out.toByteArray(), charset));
    }

    /**
     * Structural pre-check: size cap and no DOCTYPE / ENTITY declarations (case-insensitive).
     */
    public static String requireSafeBody(String body) {
        if (body == null) {
            return "";
        }
        if (body.length() > MAX_BODY_BYTES) {
            throw new XmlRejectedException("XML body too large");
        }
        if (DTD_DECLARATION.matcher(body).find()) {
            throw new XmlRejectedException("DOCTYPE and ENTITY declarations are not allowed");
        }
        return body;
    }

    /** Hardened SAXParserFactory (features set on the factory instance). */
    public static SAXParserFactory newSaxParserFactory() throws ParserConfigurationException, SAXException {
        SAXParserFactory spf = SAXParserFactory.newInstance();
        spf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        spf.setFeature(DISALLOW_DOCTYPE, true);
        spf.setFeature(EXTERNAL_GENERAL, false);
        spf.setFeature(EXTERNAL_PARAMETER, false);
        spf.setFeature(LOAD_EXTERNAL_DTD, false);
        spf.setXIncludeAware(false);
        return spf;
    }

    /** Hardened SAXParser with ACCESS_EXTERNAL_* cleared on the parser instance. */
    public static SAXParser newSaxParser() throws ParserConfigurationException, SAXException {
        SAXParser parser = newSaxParserFactory().newSAXParser();
        try {
            parser.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, "");
            parser.setProperty(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
        } catch (SAXException e) {
            // Property unsupported by this parser implementation; DOCTYPE is already disallowed.
        }
        return parser;
    }

    /** Hardened XMLReader with an empty entity resolver. */
    public static XMLReader newXMLReader() throws ParserConfigurationException, SAXException {
        XMLReader reader = newSaxParser().getXMLReader();
        reader.setEntityResolver(EMPTY_RESOLVER);
        return reader;
    }

    /** Parse with a hardened JDOM SAXBuilder. */
    public static Document parseJdom(String xml) throws JDOMException, IOException {
        SAXBuilder builder = new SAXBuilder(new XMLReaderJDOMFactory() {
            @Override
            public XMLReader createXMLReader() throws JDOMException {
                try {
                    return newXMLReader();
                } catch (SAXException | ParserConfigurationException e) {
                    throw new JDOMException("Unable to create hardened XMLReader", e);
                }
            }

            @Override
            public boolean isValidating() {
                return false;
            }
        });
        builder.setExpandEntities(false);
        builder.setEntityResolver(EMPTY_RESOLVER);
        builder.setFeature(DISALLOW_DOCTYPE, true);
        builder.setFeature(EXTERNAL_GENERAL, false);
        builder.setFeature(EXTERNAL_PARAMETER, false);
        builder.setFeature(LOAD_EXTERNAL_DTD, false);
        return builder.build(new InputSource(new StringReader(xml)));
    }

    /** Parse with a hardened Commons Digester (no rules registered). */
    public static void parseDigester(String xml) throws IOException, SAXException, ParserConfigurationException {
        Digester digester = new Digester();
        digester.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        digester.setFeature(DISALLOW_DOCTYPE, true);
        digester.setFeature(EXTERNAL_GENERAL, false);
        digester.setFeature(EXTERNAL_PARAMETER, false);
        digester.setFeature(LOAD_EXTERNAL_DTD, false);
        digester.setEntityResolver(EMPTY_RESOLVER);
        try {
            digester.setFeature(XINCLUDE, false);
        } catch (Exception e) {
            // Optional hardening unsupported by this parser implementation; DOCTYPE is disallowed.
        }
        try {
            digester.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, "");
            digester.setProperty(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
        } catch (Exception e) {
            // Optional hardening unsupported by this parser implementation; DOCTYPE is disallowed.
        }
        digester.parse(new StringReader(xml));
    }
}
