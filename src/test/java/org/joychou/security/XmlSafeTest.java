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
    public void rebuildKeepsBenignXml() throws Exception {
        String out = XmlSafe.rebuild("<root a=\"1\"><a>x &amp; y</a><b><![CDATA[<z>]]></b><!-- c --></root>");
        assertTrue(out.contains("<a>x &amp; y</a>"));
        assertTrue(out.contains("&lt;z>") || out.contains("&lt;z&gt;"));
        assertTrue(!out.contains("<!--"));
        XmlSafe.newDocumentBuilder(true).parse(src(out));
        XmlSafe.newDigester().parse(new StringReader(out));
    }

    @Test(expected = IOException.class)
    public void rebuildRejectsDoctypeAndEntity() throws IOException {
        XmlSafe.rebuild(XXE);
    }

    @Test(expected = IOException.class)
    public void rebuildRejectsMixedCaseDoctype() throws IOException {
        XmlSafe.rebuild("<?xml version=\"1.0\"?><!DocType r><r/>");
    }

    @Test(expected = IOException.class)
    public void rebuildRejectsNulPaddedDoctype() throws IOException {
        XmlSafe.rebuild("<r/>\u0000<\u0000!\u0000E\u0000N\u0000T\u0000I\u0000T\u0000Y\u0000 x>");
    }

    @Test(expected = IOException.class)
    public void rebuildRejectsStylesheet() throws IOException {
        XmlSafe.rebuild("<?xml-stylesheet href=\"x.xsl\"?><r/>");
    }

    @Test(expected = IOException.class)
    public void rebuildRejectsMalformed() throws IOException {
        XmlSafe.rebuild("<r><a></r>");
    }

    @Test(expected = IOException.class)
    public void rebuildRejectsEmpty() throws IOException {
        XmlSafe.rebuild("");
    }

    @Test(expected = IOException.class)
    public void rebuildRejectsOversize() throws IOException {
        StringBuilder sb = new StringBuilder("<r>");
        for (int i = 0; i <= XmlSafe.MAX_XML_CHARS; i++) {
            sb.append('a');
        }
        XmlSafe.rebuild(sb.append("</r>").toString());
    }

    @Test
    public void sanitizeKeepsBenignXml() throws IOException {
        byte[] out = XmlSafe.sanitizeXml(OK.getBytes(StandardCharsets.UTF_8));
        assertTrue(new String(out, StandardCharsets.UTF_8).contains("<a>1</a>"));
    }
}
