package org.joychou.controller.othervulns;

import com.monitorjbl.xlsx.StreamingReader;
import org.apache.poi.ss.usermodel.Workbook;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.multipart.MultipartFile;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
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
        // xlsx-streamer 2.0.0 parses the workbook XML with entity resolution enabled and
        // exposes no parser configuration, so reject any package containing a DTD first.
        rejectXmlWithDoctype(file.getInputStream());
        StreamingReader.builder().open(file.getInputStream());
    }


    /**
     * Scan every XML part of the OOXML (zip) package and reject it if any part is not plain
     * ASCII-compatible XML or declares a DOCTYPE (needed for any external entity / DTD).
     */
    private static void rejectXmlWithDoctype(InputStream upload) throws IOException {
        final byte[] doctype = "<!DOCTYPE".getBytes(StandardCharsets.US_ASCII);
        final long maxTotalBytes = 512L * 1024 * 1024;
        long total = 0;
        byte[] buf = new byte[8192];

        try (ZipInputStream zip = new ZipInputStream(upload)) {
            ZipEntry entry;
            while ((entry = zip.getNextEntry()) != null) {
                String name = entry.getName().toLowerCase(Locale.ROOT);
                if (entry.isDirectory() || !(name.endsWith(".xml") || name.endsWith(".rels"))) {
                    continue;
                }
                byte[] window = new byte[0];
                boolean first = true;
                int n;
                while ((n = zip.read(buf)) != -1) {
                    total += n;
                    if (total > maxTotalBytes) {
                        throw new IllegalArgumentException("xlsx package too large");
                    }
                    if (first) {
                        int off = 0;
                        if (n >= 3 && (buf[0] & 0xFF) == 0xEF && (buf[1] & 0xFF) == 0xBB && (buf[2] & 0xFF) == 0xBF) {
                            off = 3;
                        }
                        // XML must start with '<' followed by a non-NUL byte; this rejects
                        // UTF-16/UTF-32/EBCDIC encoded parts that could hide a DOCTYPE.
                        if (n < off + 2 || buf[off] != '<' || buf[off + 1] == 0) {
                            throw new IllegalArgumentException("unsupported xml encoding in xlsx");
                        }
                        first = false;
                    }
                    byte[] data = new byte[window.length + n];
                    System.arraycopy(window, 0, data, 0, window.length);
                    System.arraycopy(buf, 0, data, window.length, n);
                    if (indexOf(data, doctype) >= 0) {
                        throw new IllegalArgumentException("DOCTYPE is not allowed in xlsx xml");
                    }
                    int keep = Math.min(doctype.length - 1, data.length);
                    window = new byte[keep];
                    System.arraycopy(data, data.length - keep, window, 0, keep);
                }
            }
        }
    }

    private static int indexOf(byte[] data, byte[] pattern) {
        outer:
        for (int i = 0; i <= data.length - pattern.length; i++) {
            for (int j = 0; j < pattern.length; j++) {
                if (data[i + j] != pattern[j]) {
                    continue outer;
                }
            }
            return i;
        }
        return -1;
    }


    public static void main(String[] args) throws Exception {
        StreamingReader.builder().open((new FileInputStream("poc.xlsx")));
    }
}
