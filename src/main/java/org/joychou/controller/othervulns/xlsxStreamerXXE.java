package org.joychou.controller.othervulns;

import com.monitorjbl.xlsx.StreamingReader;
import org.apache.poi.ss.usermodel.Workbook;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.multipart.MultipartFile;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
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
        byte[] data = file.getBytes();
        rejectIfXxePayload(data);
        StreamingReader.builder().open(new ByteArrayInputStream(data));
    }


    public static void main(String[] args) throws Exception {
        byte[] data = Files.readAllBytes(new File("poc.xlsx").toPath());
        rejectIfXxePayload(data);
        StreamingReader.builder().open(new ByteArrayInputStream(data));
    }

    /**
     * Scan every XML entry inside the XLSX ZIP archive and reject the file
     * if any entry contains a DOCTYPE declaration (which could define
     * external or internal entities, enabling XXE attacks).
     */
    private static void rejectIfXxePayload(byte[] xlsxBytes) throws IOException {
        try (ZipInputStream zis = new ZipInputStream(new ByteArrayInputStream(xlsxBytes))) {
            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                String name = entry.getName().toLowerCase();
                if (name.endsWith(".xml") || name.endsWith(".rels")) {
                    byte[] buf = readAllBytes(zis);
                    String content = new String(buf, StandardCharsets.UTF_8);
                    if (content.contains("<!DOCTYPE") || content.contains("<!ENTITY")) {
                        throw new IOException("XLSX rejected: XML entry contains DOCTYPE/ENTITY declaration (potential XXE)");
                    }
                }
                zis.closeEntry();
            }
        }
    }

    /** Read all remaining bytes from the current ZIP entry (Java 8 compatible). */
    private static byte[] readAllBytes(ZipInputStream zis) throws IOException {
        java.io.ByteArrayOutputStream bos = new java.io.ByteArrayOutputStream(4096);
        byte[] tmp = new byte[4096];
        int n;
        while ((n = zis.read(tmp)) != -1) {
            bos.write(tmp, 0, n);
        }
        return bos.toByteArray();
    }
}
