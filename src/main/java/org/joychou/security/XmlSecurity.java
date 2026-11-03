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
import java.io.StringWriter;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.Charset;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.xml.transform.ErrorListener;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.sax.SAXSource;
import javax.xml.transform.stream.StreamResult;
import org.xml.sax.SAXException;

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

    private static final Pattern DANGEROUS_MARKUP = Pattern.compile(
            "<!DOCTYPE|<!ENTITY|<!ELEMENT|<!ATTLIST|<\\?xml-stylesheet|xi:include|xinclude",
            Pattern.CASE_INSENSITIVE);
    private static final Pattern XML_DECL_ENCODING = Pattern.compile(
            "\\A\\uFEFF?\\s*<\\?xml\\s[^>]*?encoding\\s*=\\s*[\"']([^\"']+)[\"']",
            Pattern.CASE_INSENSITIVE);

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
            String body = new String(out.toByteArray(), charset);
            rejectDangerousMarkup(body);
            return body;
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
        rejectDangerousMarkup(xml);
        XMLReader reader = newXMLReader();
        reader.setContentHandler(new DefaultHandler());
        reader.parse(new InputSource(new StringReader(xml)));
    }

    /** Same as {@link #requireSafeXml(String)} for raw bytes (must be UTF-8 / ASCII). */
    public static void requireSafeXml(byte[] xml) throws Exception {
        requireSafeXml(decodeStrict(xml));
    }

    /**
     * Strict pre-parse gate on the raw XML text. Rejects DOCTYPE / ENTITY / ELEMENT / ATTLIST
     * declarations (which also covers SYSTEM / PUBLIC identifiers, as those can only appear
     * inside a DOCTYPE), stylesheet processing instructions, XInclude and any XML declaration
     * that names an encoding other than UTF-8 / US-ASCII.
     */
    public static void rejectDangerousMarkup(CharSequence xml) throws IOException {
        if (xml == null) {
            throw new IOException("empty XML");
        }
        if (DANGEROUS_MARKUP.matcher(xml).find()) {
            throw new IOException("DTD, entity, stylesheet or XInclude markup is not allowed");
        }
        Matcher m = XML_DECL_ENCODING.matcher(xml);
        if (m.find()) {
            String enc = m.group(1).toUpperCase(Locale.ROOT);
            if (!(enc.equals("UTF-8") || enc.equals("US-ASCII") || enc.equals("ASCII"))) {
                throw new IOException("unsupported XML encoding declaration");
            }
        }
        for (int i = 0, n = xml.length(); i < n; i++) {
            if (xml.charAt(i) == 0) {
                throw new IOException("NUL character in XML");
            }
        }
    }

    /**
     * Gate the text, parse it once with the hardened reader and re-serialize a canonical
     * document built only from the parsed element / attribute / text events. Callers must hand
     * the returned string (never the original request text) to downstream XML consumers.
     */
    public static String canonicalize(String xml) throws IOException, SAXException {
        rejectDangerousMarkup(xml);
        try {
            TransformerFactory tf = TransformerFactory.newInstance();
            tf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            tf.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
            tf.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "");
            Transformer transformer = tf.newTransformer();
            transformer.setOutputProperty(OutputKeys.METHOD, "xml");
            transformer.setOutputProperty(OutputKeys.ENCODING, "UTF-8");
            transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
            transformer.setErrorListener(new ErrorListener() {
                @Override
                public void warning(TransformerException e) {
                    // ignore warnings
                }

                @Override
                public void error(TransformerException e) throws TransformerException {
                    throw e;
                }

                @Override
                public void fatalError(TransformerException e) throws TransformerException {
                    throw e;
                }
            });
            StringWriter out = new StringWriter();
            transformer.transform(
                    new SAXSource(newXMLReader(), new InputSource(new StringReader(xml))),
                    new StreamResult(out));
            return out.toString();
        } catch (TransformerException | RuntimeException e) {
            throw new SAXException("invalid XML", e);
        }
    }

    /** Same as {@link #canonicalize(String)} for raw bytes, which must be UTF-8 / ASCII. */
    public static String canonicalize(byte[] xml) throws IOException, SAXException {
        return canonicalize(decodeStrict(xml));
    }

    private static String decodeStrict(byte[] xml) throws IOException {
        int off = (xml.length >= 3 && (xml[0] & 0xFF) == 0xEF && (xml[1] & 0xFF) == 0xBB
                && (xml[2] & 0xFF) == 0xBF) ? 3 : 0;
        try {
            return StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(xml, off, xml.length - off))
                    .toString();
        } catch (CharacterCodingException e) {
            throw new IOException("XML must be UTF-8 or ASCII", e);
        }
    }
}
