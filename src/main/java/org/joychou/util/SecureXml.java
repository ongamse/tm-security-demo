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
import java.util.ArrayDeque;
import java.util.Deque;
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

    private static final int MAX_DEPTH = 256;
    private static final int MAX_ATTRIBUTES = 256;

    /** Printable ASCII 0x20..0x7E; the only source of characters emitted by the rebuild. */
    private static final String PRINTABLE =
            " !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~";
    private static final String DIGITS = "0123456789";

    private static final Pattern NAME =
            Pattern.compile("[A-Za-z_][A-Za-z0-9_.\\-]*(?::[A-Za-z_][A-Za-z0-9_.\\-]*)?");
    private static final Pattern NUMERIC_REF = Pattern.compile("#(?:[0-9]{1,7}|x[0-9A-Fa-f]{1,6})");
    private static final Pattern XML_DECL = Pattern.compile(
            "[ \\t\\r\\n]+version[ \\t\\r\\n]*=[ \\t\\r\\n]*([\"'])1\\.[0-9]+\\1"
                    + "(?:[ \\t\\r\\n]+encoding[ \\t\\r\\n]*=[ \\t\\r\\n]*([\"'])[A-Za-z][A-Za-z0-9._\\-]*\\2)?"
                    + "(?:[ \\t\\r\\n]+standalone[ \\t\\r\\n]*=[ \\t\\r\\n]*([\"'])(?:yes|no)\\3)?"
                    + "[ \\t\\r\\n]*");

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

    /**
     * Validate an untrusted XML document with a strict whitelist scanner and return a canonical copy
     * (default size cap {@link #MAX_BODY_BYTES}). See {@link #canonicalize(String, int)}.
     */
    public static String canonicalize(String xml) {
        return canonicalize(xml, MAX_BODY_BYTES);
    }

    /**
     * Validate an untrusted XML document with a strict whitelist scanner and rebuild it.
     *
     * The scanner never hands the untrusted string to an XML parser. It accepts only elements and
     * attributes with ASCII names, text and attribute values whose only references are the five
     * predefined entities and numeric character references, comments (dropped), CDATA sections
     * (re-emitted as escaped text) and a leading XML declaration (dropped). A DOCTYPE or any other
     * "&lt;!" construct, processing instructions and invalid characters are refused. Nesting depth,
     * attribute count and size are limited.
     *
     * The returned string is assembled only from server-owned constants (printable ASCII table
     * lookups, fixed escape sequences and numeric character references), so it carries no
     * DTD/entity/XInclude machinery and parses to the same infoset as the accepted input.
     *
     * @throws XmlRejectedException if a DOCTYPE/ENTITY, processing instruction or oversize input is found
     * @throws IllegalArgumentException if the document is not well formed within the accepted subset
     */
    public static String canonicalize(String xml, int maxChars) {
        if (xml == null || xml.isEmpty()) {
            throw malformed();
        }
        if (xml.length() > maxChars) {
            throw new XmlRejectedException("XML body too large");
        }
        final int len = xml.length();
        StringBuilder out = new StringBuilder(len + 16);
        Deque<String> open = new ArrayDeque<String>();
        int i = 0;
        if (xml.codePointAt(0) == 0xFEFF) {
            i = 1;
        }
        if (xml.startsWith("<?xml", i) && i + 5 < len && isXmlSpace(xml.charAt(i + 5))) {
            int end = xml.indexOf("?>", i + 5);
            if (end < 0 || !XML_DECL.matcher(xml.substring(i + 5, end)).matches()) {
                throw malformed();
            }
            i = end + 2;
        }
        boolean rootSeen = false;
        while (i < len) {
            if (xml.charAt(i) != '<') {
                int next = xml.indexOf('<', i);
                if (next < 0) {
                    next = len;
                }
                if (open.isEmpty()) {
                    for (int k = i; k < next; k++) {
                        if (!isXmlSpace(xml.charAt(k))) {
                            throw malformed();
                        }
                    }
                } else {
                    appendContent(out, xml, i, next, false, true);
                }
                i = next;
                continue;
            }
            if (xml.startsWith("<!--", i)) {
                int end = xml.indexOf("-->", i + 4);
                if (end < 0) {
                    throw malformed();
                }
                String comment = xml.substring(i + 4, end);
                if (comment.contains("--") || comment.endsWith("-")) {
                    throw malformed();
                }
                i = end + 3;
                continue;
            }
            if (xml.startsWith("<![CDATA[", i)) {
                int end = xml.indexOf("]]>", i + 9);
                if (open.isEmpty() || end < 0) {
                    throw malformed();
                }
                appendContent(out, xml, i + 9, end, false, false);
                i = end + 3;
                continue;
            }
            if (i + 1 >= len) {
                throw malformed();
            }
            char d = xml.charAt(i + 1);
            if (d == '!') {
                throw new XmlRejectedException("DOCTYPE and ENTITY declarations are not allowed");
            }
            if (d == '?') {
                throw new XmlRejectedException("Processing instructions are not allowed");
            }
            if (d == '/') {
                int end = xml.indexOf('>', i + 2);
                if (end < 0) {
                    throw malformed();
                }
                String name = stripTrailingXmlSpace(xml.substring(i + 2, end));
                String expected = open.poll();
                if (expected == null || !NAME.matcher(name).matches() || !expected.equals(name)) {
                    throw malformed();
                }
                out.append("</");
                appendAscii(out, name);
                out.append('>');
                i = end + 1;
                continue;
            }
            // start tag
            int nameEnd = i + 1;
            while (nameEnd < len && isNameChar(xml.charAt(nameEnd))) {
                nameEnd++;
            }
            String name = xml.substring(i + 1, nameEnd);
            if (!NAME.matcher(name).matches() || (open.isEmpty() && rootSeen) || open.size() >= MAX_DEPTH) {
                throw malformed();
            }
            out.append('<');
            appendAscii(out, name);
            int j = nameEnd;
            int attrs = 0;
            boolean selfClose = false;
            while (true) {
                int wsStart = j;
                while (j < len && isXmlSpace(xml.charAt(j))) {
                    j++;
                }
                if (j >= len) {
                    throw malformed();
                }
                char ch = xml.charAt(j);
                if (ch == '>') {
                    j++;
                    break;
                }
                if (ch == '/') {
                    if (j + 1 < len && xml.charAt(j + 1) == '>') {
                        selfClose = true;
                        j += 2;
                        break;
                    }
                    throw malformed();
                }
                if (j == wsStart || ++attrs > MAX_ATTRIBUTES) {
                    throw malformed();
                }
                int attrStart = j;
                while (j < len && isNameChar(xml.charAt(j))) {
                    j++;
                }
                String attrName = xml.substring(attrStart, j);
                if (!NAME.matcher(attrName).matches()) {
                    throw malformed();
                }
                while (j < len && isXmlSpace(xml.charAt(j))) {
                    j++;
                }
                if (j >= len || xml.charAt(j) != '=') {
                    throw malformed();
                }
                j++;
                while (j < len && isXmlSpace(xml.charAt(j))) {
                    j++;
                }
                if (j >= len) {
                    throw malformed();
                }
                char quote = xml.charAt(j);
                if (quote != '"' && quote != '\'') {
                    throw malformed();
                }
                int valueEnd = xml.indexOf(quote, j + 1);
                if (valueEnd < 0) {
                    throw malformed();
                }
                out.append(' ');
                appendAscii(out, attrName);
                out.append("=\"");
                appendContent(out, xml, j + 1, valueEnd, true, true);
                out.append('"');
                j = valueEnd + 1;
            }
            if (open.isEmpty()) {
                rootSeen = true;
            }
            if (selfClose) {
                out.append("/>");
            } else {
                out.append('>');
                open.push(name);
            }
            i = j;
        }
        if (!open.isEmpty() || !rootSeen) {
            throw malformed();
        }
        return out.toString();
    }

    /**
     * Rebuild a printable-ASCII string (for example a zip entry name) from the server-owned
     * character table. Anything else is refused.
     */
    public static String asciiCopy(String value) {
        if (value == null || value.isEmpty() || value.length() > 255) {
            throw malformed();
        }
        StringBuilder sb = new StringBuilder(value.length());
        appendAscii(sb, value);
        return sb.toString();
    }

    private static IllegalArgumentException malformed() {
        return new IllegalArgumentException("Malformed or unsupported XML");
    }

    private static boolean isXmlSpace(char c) {
        return c == ' ' || c == '\t' || c == '\r' || c == '\n';
    }

    private static boolean isNameChar(char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
                || c == '_' || c == '.' || c == '-' || c == ':';
    }

    private static boolean isXmlChar(int cp) {
        return cp == 0x9 || cp == 0xA || cp == 0xD
                || (cp >= 0x20 && cp <= 0xD7FF)
                || (cp >= 0xE000 && cp <= 0xFFFD)
                || (cp >= 0x10000 && cp <= 0x10FFFF);
    }

    private static String stripTrailingXmlSpace(String s) {
        int end = s.length();
        while (end > 0 && isXmlSpace(s.charAt(end - 1))) {
            end--;
        }
        return s.substring(0, end);
    }

    private static void appendAscii(StringBuilder out, String s) {
        for (int k = 0; k < s.length(); k++) {
            char c = s.charAt(k);
            if (c < 0x20 || c > 0x7E) {
                throw malformed();
            }
            out.append(PRINTABLE.charAt(c - 0x20));
        }
    }

    /**
     * Append the text between {@code from} and {@code to}, resolving references (when
     * {@code refs}) and re-emitting every character through {@link #emit}.
     */
    private static void appendContent(StringBuilder out, String s, int from, int to, boolean attr, boolean refs) {
        int k = from;
        while (k < to) {
            int cp = s.codePointAt(k);
            if (!isXmlChar(cp)) {
                throw malformed();
            }
            if (cp == '&' && refs) {
                int semi = s.indexOf(';', k + 1);
                if (semi < 0 || semi >= to || semi - k > 10) {
                    throw malformed();
                }
                emit(out, decodeReference(s.substring(k + 1, semi)), true, attr);
                k = semi + 1;
                continue;
            }
            if (cp == '<' && attr && refs) {
                throw malformed();
            }
            if (cp == '\r') {
                if (k + 1 < to && s.charAt(k + 1) == '\n') {
                    k++;
                    continue;
                }
                cp = '\n';
            }
            emit(out, cp, false, attr);
            k += Character.charCount(cp);
        }
    }

    private static int decodeReference(String ref) {
        switch (ref) {
            case "amp":
                return '&';
            case "lt":
                return '<';
            case "gt":
                return '>';
            case "quot":
                return '"';
            case "apos":
                return '\'';
            default:
                break;
        }
        if (!NUMERIC_REF.matcher(ref).matches()) {
            throw malformed();
        }
        boolean hex = ref.charAt(1) == 'x';
        int cp = Integer.parseInt(ref.substring(hex ? 2 : 1), hex ? 16 : 10);
        if (!isXmlChar(cp)) {
            throw malformed();
        }
        return cp;
    }

    /** Emit one character using only constants / table lookups. */
    private static void emit(StringBuilder out, int cp, boolean viaRef, boolean attr) {
        switch (cp) {
            case '&':
                out.append("&amp;");
                return;
            case '<':
                out.append("&lt;");
                return;
            case '>':
                out.append("&gt;");
                return;
            case '"':
                out.append("&quot;");
                return;
            case '\t':
                if (viaRef) {
                    out.append("&#9;");
                } else if (attr) {
                    out.append(' ');
                } else {
                    out.append('\t');
                }
                return;
            case '\n':
                if (viaRef) {
                    out.append("&#10;");
                } else if (attr) {
                    out.append(' ');
                } else {
                    out.append('\n');
                }
                return;
            case '\r':
                out.append("&#13;");
                return;
            default:
                if (cp >= 0x20 && cp <= 0x7E) {
                    out.append(PRINTABLE.charAt(cp - 0x20));
                } else {
                    out.append("&#");
                    int div = 1;
                    while (cp / div >= 10) {
                        div *= 10;
                    }
                    while (div > 0) {
                        out.append(DIGITS.charAt((cp / div) % 10));
                        div /= 10;
                    }
                    out.append(';');
                }
        }
    }

    /** Parse with a hardened JDOM SAXBuilder; only the rebuilt, validated document is parsed. */
    public static Document parseJdom(String xml) throws JDOMException, IOException {
        String canonical = canonicalize(xml);
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
        return builder.build(new StringReader(canonical));
    }

    /** Parse with a hardened Commons Digester (no rules registered). */
    public static void parseDigester(String xml) throws IOException, SAXException, ParserConfigurationException {
        String canonical = canonicalize(xml);
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
        digester.parse(new StringReader(canonical));
    }
}
