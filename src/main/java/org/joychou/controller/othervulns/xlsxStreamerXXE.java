package org.joychou.controller.othervulns;

import com.monitorjbl.xlsx.StreamingReader;
import org.apache.poi.ss.usermodel.Workbook;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.multipart.MultipartFile;

import org.joychou.util.XmlSecurity;

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


    @GetMapping("/upload")
    public String index() {
        return "xxe_upload"; // return xxe_upload.html page
    }


    @PostMapping("/readxlsx")
    public void xllx_streamer_xxe(MultipartFile file) throws IOException {
        // Reject workbooks whose XML parts declare a DOCTYPE/ENTITY and rewrite every XML part through a
        // hardened StAX reader; only the sanitized package reaches the streaming reader.
        try (InputStream check = file.getInputStream()) {
            assertNoDoctype(check);
        }
        ByteArrayOutputStream sanitized = new ByteArrayOutputStream();
        try (InputStream upload = file.getInputStream()) {
            XmlSecurity.sanitizeOoxml(upload, sanitized);
        }
        StreamingReader.builder().open(new ByteArrayInputStream(sanitized.toByteArray()));
    }


    /**
     * Fail closed if any XML part of the OOXML package is not plain ASCII-compatible XML
     * or contains a DOCTYPE declaration (which is required for any XXE payload).
     */
    private static void assertNoDoctype(InputStream in) throws IOException {
        final byte[] marker = "<!DOCTYPE".getBytes("US-ASCII");
        ZipInputStream zis = new ZipInputStream(in);
        byte[] buf = new byte[8192];
        ZipEntry entry;
        while ((entry = zis.getNextEntry()) != null) {
            String name = entry.getName().toLowerCase();
            if (!(name.endsWith(".xml") || name.endsWith(".rels"))) {
                continue;
            }
            int matched = 0;      // KMP-free rolling match: marker has no repeated prefix
            long total = 0;
            int n;
            while ((n = zis.read(buf)) != -1) {
                for (int i = 0; i < n; i++, total++) {
                    byte b = buf[i];
                    // The first byte of an ASCII-compatible XML part must be '<' (optionally after a UTF-8 BOM);
                    // this rejects UTF-16/UTF-32/EBCDIC encoded parts that could hide a DOCTYPE.
                    if (total == 0 && b != '<' && b != (byte) 0xEF) {
                        throw new IllegalArgumentException("unsupported XML encoding in " + entry.getName());
                    }
                    if (b == 0) {
                        throw new IllegalArgumentException("unsupported XML encoding in " + entry.getName());
                    }
                    if (b == marker[matched]) {
                        matched++;
                        if (matched == marker.length) {
                            throw new IllegalArgumentException("DOCTYPE is not allowed in " + entry.getName());
                        }
                    } else {
                        matched = (b == marker[0]) ? 1 : 0;
                    }
                }
            }
        }
    }


    public static void main(String[] args) throws Exception {
        StreamingReader.builder().open((new FileInputStream("poc.xlsx")));
    }
}
