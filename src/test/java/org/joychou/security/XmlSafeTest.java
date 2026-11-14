package org.joychou.security;

import org.junit.Test;
import org.xml.sax.InputSource;
import org.xml.sax.helpers.DefaultHandler;

import java.io.IOException;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class XmlSafeTest {

    private static final String OK = "<root><a>1</a></root>";
    private static final String XXE = "<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY x SYSTEM \"file:///etc/passwd\">]><r>&x;</r>";

    private static InputSource src(String s) {
        return new InputSource(new StringReader(s));
    }

    @Test
    public void parsesBenignXmlWithEveryFactory() throws Exception {
        assertNotNull(XmlSafe.newDocumentBuilder(true).parse(src(OK)));
        XmlSafe.newXMLReader().parse(src(OK));
        XmlSafe.newSAXParserFactory().newSAXParser().parse(src(OK), new DefaultHandler());
        assertNotNull(XmlSafe.newSAXBuilder().build(src(OK)));
        assertNotNull(XmlSafe.newSAXReader().read(src(OK)));
        XmlSafe.newDigester().parse(new StringReader(OK));
    }

    @Test(expected = Exception.class)
    public void documentBuilderRejectsDoctype() throws Exception {
        XmlSafe.newDocumentBuilder(false).parse(src(XXE));
    }

    @Test(expected = Exception.class)
    public void xmlReaderRejectsDoctype() throws Exception {
        XmlSafe.newXMLReader().parse(src(XXE));
    }

    @Test(expected = Exception.class)
    public void saxBuilderRejectsDoctype() throws Exception {
        XmlSafe.newSAXBuilder().build(src(XXE));
    }

    @Test(expected = Exception.class)
    public void saxReaderRejectsDoctype() throws Exception {
        XmlSafe.newSAXReader().read(src(XXE));
    }

    @Test(expected = Exception.class)
    public void digesterRejectsDoctype() throws Exception {
        XmlSafe.newDigester().parse(new StringReader(XXE));
    }

    @Test(expected = IOException.class)
    public void sanitizeRejectsDoctype() throws IOException {
        XmlSafe.sanitizeXml(XXE.getBytes(StandardCharsets.UTF_8));
    }

    @Test
    public void sanitizeKeepsBenignXml() throws IOException {
        byte[] out = XmlSafe.sanitizeXml(OK.getBytes(StandardCharsets.UTF_8));
        assertTrue(new String(out, StandardCharsets.UTF_8).contains("<a>1</a>"));
    }
}
