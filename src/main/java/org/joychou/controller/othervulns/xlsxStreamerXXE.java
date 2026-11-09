package org.joychou.controller.othervulns;

import com.monitorjbl.xlsx.StreamingReader;
import org.apache.poi.ss.usermodel.Workbook;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.multipart.MultipartFile;

import org.xml.sax.SAXException;
import org.xml.sax.helpers.DefaultHandler;

import javax.xml.XMLConstants;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;
import java.io.FileInputStream;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
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
        // xlsx-streamer 2.0.0 parses the package XML parts without disabling DTDs, so reject
        // any part that declares a DOCTYPE / entities before handing the upload to it.
        try (InputStream in = file.getInputStream()) {
            rejectDoctypeInXmlParts(in);
        }
        StreamingReader.builder().open(file.getInputStream());
    }


    /**
     * Parse every XML part of the xlsx (zip) package with a DOCTYPE-rejecting parser.
     *
     * @throws IOException if a part is malformed or declares a DOCTYPE (possible XXE)
     */
    private static void rejectDoctypeInXmlParts(InputStream in) throws IOException {
        try {
            SAXParserFactory spf = SAXParserFactory.newInstance();
            spf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            spf.setFeature("http://xml.org/sax/features/external-general-entities", false);
            spf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            spf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            SAXParser parser = spf.newSAXParser();

            ZipInputStream zip = new ZipInputStream(in);
            ZipEntry entry;
            while ((entry = zip.getNextEntry()) != null) {
                String name = entry.getName().toLowerCase();
                if (entry.isDirectory() || !(name.endsWith(".xml") || name.endsWith(".rels"))) {
                    continue;
                }
                // Do not let the parser close the zip stream between entries.
                InputStream partStream = new FilterInputStream(zip) {
                    @Override
                    public void close() {
                        // keep the underlying zip stream open
                    }
                };
                parser.parse(partStream, new DefaultHandler());
                parser.reset();
            }
        } catch (ParserConfigurationException | SAXException e) {
            throw new IOException("Rejected xlsx: unsafe or malformed XML part", e);
        }
    }


    public static void main(String[] args) throws Exception {
        StreamingReader.builder().open((new FileInputStream("poc.xlsx")));
    }
}
