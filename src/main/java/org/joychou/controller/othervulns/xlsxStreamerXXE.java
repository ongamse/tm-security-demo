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
        // xlsx-streamer 2.0.0 parses xl/workbook.xml with an unhardened parser, so reject any
        // package whose XML parts declare a DOCTYPE (and therefore any external entity) first.
        rejectDoctypeInXlsx(file.getInputStream());
        StreamingReader.builder().open(file.getInputStream());
    }


    /**
     * Parse every XML part of the xlsx (zip) package with DOCTYPE and external entities disabled.
     * Throws IOException when a part is malformed or declares a DOCTYPE.
     */
    private static void rejectDoctypeInXlsx(InputStream in) throws IOException {
        try (ZipInputStream zip = new ZipInputStream(in)) {
            SAXParserFactory spf = SAXParserFactory.newInstance();
            spf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            spf.setFeature("http://xml.org/sax/features/external-general-entities", false);
            spf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            spf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
            spf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            spf.setNamespaceAware(true);

            ZipEntry entry;
            while ((entry = zip.getNextEntry()) != null) {
                String name = entry.getName().toLowerCase(Locale.ROOT);
                if (entry.isDirectory() || !(name.endsWith(".xml") || name.endsWith(".rels"))) {
                    continue;
                }
                // The parser closes its input at end of document; keep the zip stream open.
                InputStream part = new FilterInputStream(zip) {
                    @Override
                    public void close() {
                        // no-op
                    }
                };
                spf.newSAXParser().parse(part, new DefaultHandler());
            }
        } catch (ParserConfigurationException | SAXException e) {
            throw new IOException("Invalid or unsafe XML in xlsx package", e);
        }
    }


    public static void main(String[] args) throws Exception {
        StreamingReader.builder().open((new FileInputStream("poc.xlsx")));
    }
}
