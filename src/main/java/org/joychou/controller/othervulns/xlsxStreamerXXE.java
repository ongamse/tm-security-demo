package org.joychou.controller.othervulns;

import com.monitorjbl.xlsx.StreamingReader;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.multipart.MultipartFile;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
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

    private static final Logger logger = LoggerFactory.getLogger(xlsxStreamerXXE.class);

    /**
     * Set JVM-wide SAX parser system properties to disable external entities, mitigating XXE
     * in libraries like xlsx-streamer that do not expose parser configuration.
     * System properties affect all SAXParserFactory.newInstance() calls in this JVM.
     */
    static {
        // Disable external entities at the JVM level for SAX/DOM parsers
        System.setProperty("javax.xml.accessExternalDTD", "");
        System.setProperty("javax.xml.accessExternalSchema", "");
        System.setProperty("javax.xml.accessExternalStylesheet", "");
    }


    @GetMapping("/upload")
    public String index() {
        return "xxe_upload"; // return xxe_upload.html page
    }

    /**
     * Validates that no XML entry inside a ZIP/XLSX file contains DOCTYPE or ENTITY declarations.
     * XLSX files are ZIP archives containing XML parts; this check prevents XXE payloads
     * embedded in internal XML entries (e.g., xl/workbook.xml) from reaching the parser.
     */
    private static void validateXlsxNoDoctype(byte[] data) throws IOException {
        try (ZipInputStream zis = new ZipInputStream(new ByteArrayInputStream(data))) {
            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                String name = entry.getName().toLowerCase();
                if (name.endsWith(".xml") || name.endsWith(".rels")) {
                    ByteArrayOutputStream baos = new ByteArrayOutputStream();
                    byte[] buf = new byte[4096];
                    int len;
                    while ((len = zis.read(buf)) > 0) {
                        baos.write(buf, 0, len);
                    }
                    String content = baos.toString("UTF-8").toUpperCase();
                    if (content.contains("<!DOCTYPE") || content.contains("<!ENTITY")) {
                        throw new SecurityException(
                                "XLSX entry " + entry.getName() + " contains prohibited DOCTYPE or ENTITY declaration");
                    }
                }
                zis.closeEntry();
            }
        }
    }


    @PostMapping("/readxlsx")
    @ResponseBody
    public String xllx_streamer_xxe(MultipartFile file) throws IOException {
        // Buffer the upload so we can validate ZIP entries before parsing
        byte[] data;
        try (InputStream uploadStream = file.getInputStream();
             ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            byte[] buf = new byte[4096];
            int len;
            while ((len = uploadStream.read(buf)) > 0) {
                baos.write(buf, 0, len);
            }
            data = baos.toByteArray();
        }

        // Reject XLSX files whose internal XML entries contain DOCTYPE/ENTITY declarations
        validateXlsxNoDoctype(data);

        try (InputStream is = new ByteArrayInputStream(data)) {
            StreamingReader.builder().open(is);
        }
        return "ok";
    }


    public static void main(String[] args) throws Exception {
        try (InputStream is = new FileInputStream("poc.xlsx")) {
            StreamingReader.builder().open(is);
        }
    }
}
