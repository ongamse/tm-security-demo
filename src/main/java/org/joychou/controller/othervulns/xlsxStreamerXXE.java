package org.joychou.controller.othervulns;

import com.monitorjbl.xlsx.StreamingReader;
import org.apache.poi.ss.usermodel.Workbook;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.multipart.MultipartFile;

import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.helpers.DefaultHandler;

import javax.xml.XMLConstants;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Locale;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;


/**
 * Desc:  xlsx-streamer xxe vuln code
 * Usage: xl/workbook.xml
 * Ref:   https://www.itread01.com/hkpcyyp.html
 * Fix:   update xlsx-streamer to 2.1.0 or above
 *
 * @author JoyChou @2019-09-05
 */
@Controller
@RequestMapping("xlsx-streamer")
public class xlsxStreamerXXE {


    @GetMapping("/upload")
    public String index() {
        return "xxe_upload"; // return xxe_upload.html page
    }


    // Upload and per-XML-part limits (guard against oversized packages / zip bombs).
    private static final int MAX_UPLOAD_BYTES = 10 * 1024 * 1024;
    private static final int MAX_XML_PART_BYTES = 10 * 1024 * 1024;

    @PostMapping("/readxlsx")
    public void xllx_streamer_xxe(MultipartFile file) throws IOException {
        // xlsx-streamer 2.0.0 parses xl/workbook.xml with an unhardened parser, so the upload is
        // buffered (bounded) and every XML part is parsed with DOCTYPE and external entities
        // disabled first. Only the validated bytes are handed to StreamingReader.
        byte[] data = readBounded(file.getInputStream(), MAX_UPLOAD_BYTES);
        rejectDoctypeInXlsx(data);
        StreamingReader.builder().open(new ByteArrayInputStream(data));
    }


    private static byte[] readBounded(InputStream in, int max) throws IOException {
        try (InputStream is = in) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buf = new byte[8192];
            int total = 0;
            int n;
            while ((n = is.read(buf)) != -1) {
                total += n;
                if (total > max) {
                    throw new IOException("Upload exceeds " + max + " bytes");
                }
                out.write(buf, 0, n);
            }
            return out.toByteArray();
        }
    }


    /**
     * Parse every XML part of the xlsx (zip) package with DOCTYPE and external entities disabled.
     * Throws IOException when a part is malformed, too large, or declares a DOCTYPE.
     */
    private static void rejectDoctypeInXlsx(byte[] data) throws IOException {
        try (ZipInputStream zip = new ZipInputStream(new ByteArrayInputStream(data))) {
            SAXParserFactory spf = SAXParserFactory.newInstance();
            spf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            spf.setFeature("http://xml.org/sax/features/external-general-entities", false);
            spf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            spf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
            spf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            spf.setXIncludeAware(false);
            spf.setNamespaceAware(true);

            ZipEntry entry;
            while ((entry = zip.getNextEntry()) != null) {
                String name = entry.getName().toLowerCase(Locale.ROOT);
                if (entry.isDirectory() || !(name.endsWith(".xml") || name.endsWith(".rels"))) {
                    continue;
                }
                byte[] part = readPart(zip);
                SAXParser parser = spf.newSAXParser();
                parser.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, "");
                parser.setProperty(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
                parser.parse(new InputSource(new ByteArrayInputStream(part)), new DefaultHandler());
            }
        } catch (ParserConfigurationException | SAXException e) {
            throw new IOException("Invalid or unsafe XML in xlsx package", e);
        }
    }


    // Read the current zip entry without closing the zip stream, bounded by MAX_XML_PART_BYTES.
    private static byte[] readPart(ZipInputStream zip) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        int total = 0;
        int n;
        while ((n = zip.read(buf)) != -1) {
            total += n;
            if (total > MAX_XML_PART_BYTES) {
                throw new IOException("XML part exceeds " + MAX_XML_PART_BYTES + " bytes");
            }
            out.write(buf, 0, n);
        }
        return out.toByteArray();
    }


    public static void main(String[] args) throws Exception {
        StreamingReader.builder().open((new FileInputStream("poc.xlsx")));
    }
}
