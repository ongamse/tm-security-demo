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
import java.nio.charset.StandardCharsets;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;


/**
 * Desc:  xlsx-streamer xxe code. Uploaded XML parts that declare a DOCTYPE/ENTITY are rejected
 *        before they reach the streaming reader.
 * Usage: xl/workbook.xml
 * Ref:   https://www.itread01.com/hkpcyyp.html
 * Fix:   reject DTDs in the package XML parts; also update xlsx-streamer to 2.1.0 or above
 *
 * @author JoyChou @2019-09-05
 */
@Controller
@RequestMapping("xlsx-streamer")
public class xlsxStreamerXXE {

    private static final long MAX_XML_PART_BYTES = 50L * 1024 * 1024;

    @GetMapping("/upload")
    public String index() {
        return "xxe_upload"; // return xxe_upload.html page
    }


    @PostMapping("/readxlsx")
    public void xllx_streamer_xxe(MultipartFile file) throws IOException {
        byte[] data = file.getBytes();
        rejectDtd(data);
        StreamingReader.builder().open(new ByteArrayInputStream(data));
    }

    /**
     * Fail closed if any XML part of the OOXML package is not plain UTF-8/ASCII-compatible
     * or contains a DOCTYPE / ENTITY declaration.
     */
    private static void rejectDtd(byte[] data) throws IOException {
        try (ZipInputStream zis = new ZipInputStream(new ByteArrayInputStream(data))) {
            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                String name = entry.getName().toLowerCase();
                if (entry.isDirectory() || !(name.endsWith(".xml") || name.endsWith(".rels"))) {
                    continue;
                }
                byte[] part = readBounded(zis);
                int off = (part.length >= 3 && (part[0] & 0xFF) == 0xEF && (part[1] & 0xFF) == 0xBB
                        && (part[2] & 0xFF) == 0xBF) ? 3 : 0;
                // Reject UTF-16/32/EBCDIC encoded parts that could hide a DTD from the byte search.
                if (part.length < off + 2 || part[off] != '<' || part[off + 1] == 0) {
                    throw new IOException("unsupported XML encoding in " + entry.getName());
                }
                String text = new String(part, StandardCharsets.ISO_8859_1);
                if (text.contains("<!DOCTYPE") || text.contains("<!ENTITY")) {
                    throw new IOException("DTD not allowed in " + entry.getName());
                }
            }
        }
    }

    private static byte[] readBounded(InputStream in) throws IOException {
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        long total = 0;
        int n;
        while ((n = in.read(buf)) != -1) {
            total += n;
            if (total > MAX_XML_PART_BYTES) {
                throw new IOException("XML part too large");
            }
            out.write(buf, 0, n);
        }
        return out.toByteArray();
    }


    public static void main(String[] args) throws Exception {
        StreamingReader.builder().open((new FileInputStream("poc.xlsx")));
    }
}
