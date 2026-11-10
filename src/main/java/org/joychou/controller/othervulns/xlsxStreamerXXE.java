package org.joychou.controller.othervulns;

import com.monitorjbl.xlsx.StreamingReader;
import org.apache.poi.ss.usermodel.Workbook;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.multipart.MultipartFile;

import java.io.ByteArrayInputStream;
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


    @PostMapping("/readxlsx")
    public void xllx_streamer_xxe(MultipartFile file) throws IOException {
        // xlsx-streamer 2.0.0 parses the XML parts with an unhardened parser, so reject any
        // package whose XML parts declare a DOCTYPE/ENTITY before handing it to the library.
        // Read the upload once so the exact bytes that were checked are the bytes that get parsed.
        byte[] content = file.getBytes();
        rejectXmlWithDoctype(new ByteArrayInputStream(content));
        try (InputStream checked = new ByteArrayInputStream(content)) {
            StreamingReader.builder().open(checked);
        }
    }

    private static final long MAX_XML_PART_BYTES = 64L * 1024 * 1024;

    /**
     * Fail closed if any XML part of the OOXML zip contains a DOCTYPE or ENTITY declaration.
     * NUL bytes are stripped before matching so UTF-16/UTF-32 encoded parts are covered too.
     */
    private static void rejectXmlWithDoctype(InputStream in) throws IOException {
        try (ZipInputStream zis = new ZipInputStream(in)) {
            ZipEntry entry;
            byte[] buf = new byte[8192];
            while ((entry = zis.getNextEntry()) != null) {
                String name = entry.getName().toLowerCase(Locale.ROOT);
                if (entry.isDirectory() || !(name.endsWith(".xml") || name.endsWith(".rels") || name.endsWith(".vml"))) {
                    continue;
                }
                StringBuilder text = new StringBuilder();
                long total = 0;
                int n;
                boolean first = true;
                while ((n = zis.read(buf)) > 0) {
                    total += n;
                    if (total > MAX_XML_PART_BYTES) {
                        throw new IOException("xml part too large");
                    }
                    if (first && n >= 2 && buf[0] == 0x4C && buf[1] == 0x6F) {
                        throw new IOException("unsupported xml encoding");  // EBCDIC
                    }
                    first = false;
                    for (int i = 0; i < n; i++) {
                        if (buf[i] != 0) {
                            text.append((char) (buf[i] & 0xFF));
                        }
                    }
                    String lower = text.toString().toLowerCase(Locale.ROOT);
                    if (lower.contains("<!doctype") || lower.contains("<!entity")) {
                        throw new IOException("DOCTYPE/ENTITY declarations are not allowed");
                    }
                    // keep a short tail so a marker split across chunks is still detected
                    if (text.length() > 16) {
                        text.delete(0, text.length() - 16);
                    }
                }
            }
        }
    }


    public static void main(String[] args) throws Exception {
        StreamingReader.builder().open((new FileInputStream("poc.xlsx")));
    }
}
