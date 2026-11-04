package org.joychou.controller.othervulns;

import com.monitorjbl.xlsx.StreamingReader;
import org.apache.poi.ss.usermodel.Workbook;

import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.multipart.MultipartFile;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;


/**
 * Desc:  xlsx-streamer xxe code (fixed by xlsx-streamer 2.1.0 or above)
 * Usage: xl/workbook.xml
 * Ref:   https://www.itread01.com/hkpcyyp.html
 *
 * @author JoyChou @2019-09-05
 */
@Controller
@RequestMapping("xlsx-streamer")
public class xlsxStreamerXXE {

    /** Max uncompressed size of a single XML part that is accepted. */
    private static final int MAX_XML_PART_BYTES = 32 * 1024 * 1024;

    /** Max number of zip entries that is accepted. */
    private static final int MAX_ENTRIES = 5000;

    /** Rejected markers (DTD / entity declarations), in every encoding an XML parser may detect. */
    private static final byte[][] FORBIDDEN_MARKERS = buildForbiddenMarkers();

    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public static class InvalidWorkbookException extends RuntimeException {
        private static final long serialVersionUID = 1L;

        public InvalidWorkbookException(String message) {
            super(message);
        }
    }


    @GetMapping("/upload")
    public String index() {
        return "xxe_upload"; // return xxe_upload.html page
    }


    @PostMapping("/readxlsx")
    public void xllx_streamer_xxe(MultipartFile file) throws IOException {
        // Reject (never sanitise) any workbook that is not a plain OOXML zip without DTD / entity declarations.
        validateWorkbook(file);
        StreamingReader.builder().open(file.getInputStream());
    }


    private static byte[][] buildForbiddenMarkers() {
        String[] markers = {"<!DOCTYPE", "<!ENTITY"};
        Charset[] charsets = {StandardCharsets.UTF_8, StandardCharsets.UTF_16LE, StandardCharsets.UTF_16BE};
        byte[][] result = new byte[markers.length * charsets.length][];
        int idx = 0;
        for (String marker : markers) {
            for (Charset charset : charsets) {
                result[idx++] = marker.getBytes(charset);
            }
        }
        return result;
    }


    private static void validateWorkbook(MultipartFile file) throws IOException {
        if (file == null || file.isEmpty()) {
            throw new InvalidWorkbookException("empty upload");
        }
        String name = file.getOriginalFilename();
        if (name == null || !name.toLowerCase(Locale.ROOT).endsWith(".xlsx")) {
            throw new InvalidWorkbookException("only .xlsx files are accepted");
        }

        int entries = 0;
        boolean sawZipEntry = false;
        InputStream in = file.getInputStream();
        try {
            ZipInputStream zis = new ZipInputStream(in);
            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                sawZipEntry = true;
                if (++entries > MAX_ENTRIES) {
                    throw new InvalidWorkbookException("too many entries");
                }
                String entryName = entry.getName().toLowerCase(Locale.ROOT);
                if (entryName.contains("..")) {
                    throw new InvalidWorkbookException("invalid entry name");
                }
                if (entry.isDirectory() || !(entryName.endsWith(".xml") || entryName.endsWith(".rels")
                        || entryName.endsWith(".vml"))) {
                    continue;
                }
                byte[] content = readLimited(zis);
                for (byte[] marker : FORBIDDEN_MARKERS) {
                    if (indexOf(content, marker) >= 0) {
                        throw new InvalidWorkbookException("DTD / entity declarations are not allowed");
                    }
                }
            }
        } finally {
            in.close();
        }
        if (!sawZipEntry) {
            throw new InvalidWorkbookException("not a valid xlsx file");
        }
    }


    private static byte[] readLimited(InputStream in) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        int total = 0;
        int n;
        while ((n = in.read(buf)) != -1) {
            total += n;
            if (total > MAX_XML_PART_BYTES) {
                throw new InvalidWorkbookException("xml part too large");
            }
            out.write(buf, 0, n);
        }
        return out.toByteArray();
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
