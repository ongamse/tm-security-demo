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
import javax.xml.parsers.SAXParserFactory;
import java.io.FileInputStream;
import java.io.FilterInputStream;
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


    @PostMapping("/readxlsx")
    public void xllx_streamer_xxe(MultipartFile file) throws IOException {
        // xlsx-streamer 2.0.0 parses the workbook XML parts with an unhardened parser.
        // Reject any part that declares a DOCTYPE/external entity before handing the file over.
        rejectXmlWithDoctype(file.getInputStream());
        StreamingReader.builder().open(file.getInputStream());
    }


    /**
     * Parse every XML part of the xlsx (zip) with DOCTYPE declarations disallowed, so entity
     * based payloads (XXE) are rejected before the streaming reader sees the file.
     */
    private static void rejectXmlWithDoctype(InputStream xlsx) throws IOException {
        SAXParserFactory spf = SAXParserFactory.newInstance();
        try {
            spf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            spf.setFeature("http://xml.org/sax/features/external-general-entities", false);
            spf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            spf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            spf.setNamespaceAware(true);
        } catch (ParserConfigurationException | SAXException e) {
            throw new IOException("Unable to configure secure XML parser", e);
        }

        try (ZipInputStream zis = new ZipInputStream(xlsx)) {
            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                String name = entry.getName().toLowerCase(Locale.ROOT);
                if (entry.isDirectory() || !(name.endsWith(".xml") || name.endsWith(".rels"))) {
                    continue;
                }
                // Do not let the parser close the shared zip stream.
                InputStream part = new FilterInputStream(zis) {
                    @Override
                    public void close() {
                        // no-op
                    }
                };
                try {
                    spf.newSAXParser().parse(new InputSource(part), new DefaultHandler());
                } catch (ParserConfigurationException | SAXException e) {
                    throw new IllegalArgumentException("Rejected xlsx: unsafe or malformed XML part " + entry.getName(), e);
                }
            }
        }
    }


    public static void main(String[] args) throws Exception {
        StreamingReader.builder().open((new FileInputStream("poc.xlsx")));
    }
}
