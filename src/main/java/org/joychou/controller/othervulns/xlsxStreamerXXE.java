package org.joychou.controller.othervulns;

import com.monitorjbl.xlsx.StreamingReader;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.multipart.MultipartFile;

import javax.servlet.http.HttpServletResponse;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;


/**
 * Desc:  xlsx-streamer xxe code
 * Usage: xl/workbook.xml
 * Ref:   https://www.itread01.com/hkpcyyp.html
 * Fix:   update xlsx-streamer to 2.1.0 or above; additionally every part of the uploaded
 *        package is checked and the upload is refused when any part declares a DOCTYPE or
 *        ENTITY, so no untrusted DTD / entity content ever reaches the XML parser.
 *
 * @author JoyChou @2019-09-05
 */
@Controller
@RequestMapping("xlsx-streamer")
public class xlsxStreamerXXE {

    private static final int MAX_ENTRY_BYTES = 32 * 1024 * 1024;
    private static final long MAX_TOTAL_BYTES = 256L * 1024 * 1024;
    private static final int MAX_ENTRIES = 10000;

    @GetMapping("/upload")
    public String index() {
        return "xxe_upload"; // return xxe_upload.html page
    }


    @PostMapping("/readxlsx")
    public void xllx_streamer_xxe(MultipartFile file, HttpServletResponse response) throws IOException {
        byte[] content = file.getBytes();
        if (!isSafeOoxmlPackage(content)) {
            // Refuse: the package contains DOCTYPE/ENTITY declarations or is not a bounded zip.
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "unsafe xlsx upload rejected");
            return;
        }
        StreamingReader.builder().open(new ByteArrayInputStream(content));
    }


    /**
     * Returns true only when the zip package is bounded in size and none of its parts contains
     * a DOCTYPE or ENTITY declaration (also detected inside UTF-16 encoded parts).
     */
    static boolean isSafeOoxmlPackage(byte[] content) {
        long total = 0;
        int entries = 0;
        try (ZipInputStream zis = new ZipInputStream(new ByteArrayInputStream(content))) {
            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                if (++entries > MAX_ENTRIES) {
                    return false;
                }
                byte[] part = readBounded(zis);
                if (part == null) {
                    return false;
                }
                total += part.length;
                if (total > MAX_TOTAL_BYTES) {
                    return false;
                }
                if (declaresDtdOrEntity(part)) {
                    return false;
                }
            }
        } catch (IOException | RuntimeException e) {
            return false;
        }
        return entries > 0;
    }

    private static byte[] readBounded(InputStream in) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        int n;
        while ((n = in.read(buf)) != -1) {
            if (out.size() + n > MAX_ENTRY_BYTES) {
                return null;
            }
            out.write(buf, 0, n);
        }
        return out.toByteArray();
    }

    private static boolean declaresDtdOrEntity(byte[] part) {
        // Drop NUL bytes so UTF-16 encoded markup is matched as well.
        ByteArrayOutputStream stripped = new ByteArrayOutputStream(part.length);
        for (byte b : part) {
            if (b != 0) {
                stripped.write(b);
            }
        }
        String text = new String(stripped.toByteArray(), StandardCharsets.ISO_8859_1).toLowerCase();
        return text.contains("<!doctype") || text.contains("<!entity");
    }


    public static void main(String[] args) throws Exception {
        byte[] content = java.nio.file.Files.readAllBytes(java.nio.file.Paths.get("poc.xlsx"));
        if (isSafeOoxmlPackage(content)) {
            StreamingReader.builder().open(new FileInputStream("poc.xlsx"));
        }
    }
}
