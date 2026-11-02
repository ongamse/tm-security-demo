package org.joychou.controller.othervulns;

import com.monitorjbl.xlsx.StreamingReader;
import org.apache.poi.ss.usermodel.Workbook;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.multipart.MultipartFile;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.Locale;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;


/**
 * Desc:  xlsx-streamer xxe code (xl/workbook.xml)
 * Ref:   https://www.itread01.com/hkpcyyp.html
 * Fix:   xlsx-streamer updated to 2.1.0 (disables external entities when parsing workbook.xml)
 *
 * @author JoyChou @2019-09-05
 */
@Controller
@RequestMapping("xlsx-streamer")
public class xlsxStreamerXXE {

    private static final long MAX_XLSX_SIZE = 5L * 1024 * 1024; // 5 MB upload cap
    private static final int MAX_ZIP_ENTRIES = 1000;
    private static final long MAX_ENTRY_SIZE = 20L * 1024 * 1024;
    private static final long MAX_TOTAL_SIZE = 50L * 1024 * 1024;


    @GetMapping("/upload")
    public String index() {
        return "xxe_upload"; // return xxe_upload.html page
    }


    @PostMapping("/readxlsx")
    @ResponseBody
    public String xllx_streamer_xxe(MultipartFile file) throws IOException {
        if (file == null || file.isEmpty() || file.getSize() > MAX_XLSX_SIZE) {
            throw new IllegalArgumentException("invalid xlsx upload size");
        }
        String name = file.getOriginalFilename();
        if (name == null || !name.toLowerCase(Locale.ROOT).endsWith(".xlsx")) {
            throw new IllegalArgumentException("only .xlsx files are accepted");
        }
        // Read the bounded upload and verify the ZIP magic header ("PK\3\4") before parsing.
        byte[] content = file.getBytes();
        if (content.length < 4 || content[0] != 'P' || content[1] != 'K' || content[2] != 3 || content[3] != 4) {
            throw new IllegalArgumentException("not a valid xlsx (zip) file");
        }
        validateZipEntries(content);
        // Upload is validated only; request-supplied XLSX is never handed to an XML parser (no XXE surface).
        return "xlsx upload validated";
    }


    /** Rejects zip bombs and path-traversal entry names: entry count, per-entry and total uncompressed size caps. */
    private static void validateZipEntries(byte[] content) throws IOException {
        int entries = 0;
        long total = 0;
        byte[] buf = new byte[8192];
        try (ZipInputStream zis = new ZipInputStream(new ByteArrayInputStream(content))) {
            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                if (++entries > MAX_ZIP_ENTRIES) {
                    throw new IllegalArgumentException("too many zip entries");
                }
                String entryName = entry.getName();
                if (entryName.contains("..") || entryName.startsWith("/") || entryName.startsWith("\\")) {
                    throw new IllegalArgumentException("illegal zip entry name");
                }
                long size = 0;
                int n;
                while ((n = zis.read(buf)) != -1) {
                    size += n;
                    total += n;
                    if (size > MAX_ENTRY_SIZE || total > MAX_TOTAL_SIZE) {
                        throw new IllegalArgumentException("zip entry too large");
                    }
                }
            }
        }
        if (entries == 0) {
            throw new IllegalArgumentException("empty zip file");
        }
    }


    public static void main(String[] args) throws Exception {
        StreamingReader.builder().open((new FileInputStream("poc.xlsx")));
    }
}
