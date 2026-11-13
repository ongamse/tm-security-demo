package org.joychou.controller.othervulns;

import com.monitorjbl.xlsx.StreamingReader;
import org.apache.poi.ss.usermodel.Workbook;

import org.joychou.util.XmlSecurity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.multipart.MultipartFile;

import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.ByteArrayInputStream;
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


    private static final int MAX_UPLOAD_BYTES = 10 * 1024 * 1024;

    @GetMapping("/upload")
    public String index() {
        return "xxe_upload"; // return xxe_upload.html page
    }


    @PostMapping("/readxlsx")
    public void xllx_streamer_xxe(MultipartFile file) throws IOException {
        byte[] content = file.getBytes();
        if (content.length < 4 || content.length > MAX_UPLOAD_BYTES
                || content[0] != 'P' || content[1] != 'K') {
            throw new IOException("Not a valid xlsx (zip) file or file too large");
        }
        rejectXmlDoctype(content);
        StreamingReader.builder().open(new ByteArrayInputStream(content));
    }


    /**
     * Parse every XML part of the xlsx package with DOCTYPE and external entities disabled,
     * so a crafted part (e.g. xl/workbook.xml) carrying a DTD is rejected before xlsx-streamer reads it.
     */
    private static void rejectXmlDoctype(byte[] content) throws IOException {
        try {
            DocumentBuilderFactory dbf = XmlSecurity.newDocumentBuilderFactory();
            DocumentBuilder db = dbf.newDocumentBuilder();
            try (ZipInputStream zis = new ZipInputStream(new ByteArrayInputStream(content))) {
                ZipEntry entry;
                while ((entry = zis.getNextEntry()) != null) {
                    String name = entry.getName().toLowerCase();
                    if (name.endsWith(".xml") || name.endsWith(".rels")) {
                        db.parse(new InputSource(new NonClosingInputStream(zis)));
                    }
                }
            }
        } catch (ParserConfigurationException | SAXException e) {
            throw new IOException("Invalid or unsafe XML in xlsx file", e);
        }
    }


    private static final class NonClosingInputStream extends FilterInputStream {
        NonClosingInputStream(InputStream in) {
            super(in);
        }

        @Override
        public void close() {
            // keep the underlying zip stream open for the next entry
        }
    }


    public static void main(String[] args) throws Exception {
        StreamingReader.builder().open((new FileInputStream("poc.xlsx")));
    }
}
