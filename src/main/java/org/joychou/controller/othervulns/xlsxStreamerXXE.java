package org.joychou.controller.othervulns;

import com.monitorjbl.xlsx.StreamingReader;
import org.apache.poi.ss.usermodel.Workbook;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.multipart.MultipartFile;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Enumeration;
import java.util.Locale;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
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

    private static final int MAX_XML_PART_BYTES = 64 * 1024 * 1024;

    @GetMapping("/upload")
    public String index() {
        return "xxe_upload"; // return xxe_upload.html page
    }


    @PostMapping("/readxlsx")
    public void xllx_streamer_xxe(MultipartFile file) throws IOException {
        // xlsx-streamer 2.0.0 parses the workbook XML parts with an unhardened parser and no
        // hardened release could be confirmed offline, so reject any package whose parts
        // declare a DTD / entities before handing the bytes over.
        byte[] content = file.getBytes();
        rejectXmlWithDoctype(content);
        StreamingReader.builder().open(new ByteArrayInputStream(content));
    }


    /**
     * Fail closed if any part of the OOXML (zip) package contains a DOCTYPE or ENTITY
     * declaration (UTF-8 or UTF-16), or an XML part uses an encoding that cannot be reliably
     * inspected. The package is scanned both sequentially (local headers) and through the
     * central directory (what a random-access reader uses) so that a crafted zip cannot show
     * the scanner different content than the consumer.
     */
    private static void rejectXmlWithDoctype(byte[] content) throws IOException {
        try (ZipInputStream zis = new ZipInputStream(new ByteArrayInputStream(content))) {
            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                if (!entry.isDirectory()) {
                    inspectPart(entry.getName(), zis);
                }
            }
        }
        File tmp = File.createTempFile("xlsx-scan", ".zip");
        try {
            Files.write(tmp.toPath(), content);
            try (ZipFile zf = new ZipFile(tmp)) {
                Enumeration<? extends ZipEntry> entries = zf.entries();
                while (entries.hasMoreElements()) {
                    ZipEntry entry = entries.nextElement();
                    if (!entry.isDirectory()) {
                        try (InputStream in = zf.getInputStream(entry)) {
                            inspectPart(entry.getName(), in);
                        }
                    }
                }
            }
        } finally {
            Files.deleteIfExists(tmp.toPath());
        }
    }


    private static void inspectPart(String entryName, InputStream in) throws IOException {
        String name = entryName.toLowerCase(Locale.ROOT);
        boolean xmlPart = name.endsWith(".xml") || name.endsWith(".rels");
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        byte[] chunk = new byte[8192];
        int n;
        while ((n = in.read(chunk)) != -1) {
            buf.write(chunk, 0, n);
            if (buf.size() > MAX_XML_PART_BYTES) {
                throw new IOException("XML part too large");
            }
        }
        byte[] part = buf.toByteArray();
        if (xmlPart) {
            for (byte b : part) {
                if (b == 0) {
                    throw new IOException("Unsupported XML encoding");
                }
            }
            String text = new String(part, StandardCharsets.ISO_8859_1);
            int declEnd = text.startsWith("<?xml") || text.startsWith("\u00EF\u00BB\u00BF<?xml")
                    ? text.indexOf("?>") : -1;
            if (declEnd > 0) {
                String decl = text.substring(0, declEnd).toLowerCase(Locale.ROOT);
                int enc = decl.indexOf("encoding");
                if (enc >= 0 && !decl.substring(enc).matches("(?s)encoding\\s*=\\s*[\"']utf-8[\"'].*")) {
                    throw new IOException("Unsupported XML encoding");
                }
            }
        }
        for (java.nio.charset.Charset cs : new java.nio.charset.Charset[]{
                StandardCharsets.ISO_8859_1, StandardCharsets.UTF_16LE, StandardCharsets.UTF_16BE}) {
            String text = new String(part, cs);
            if (text.contains("<!DOCTYPE") || text.contains("<!ENTITY")
                    || text.contains("<!doctype") || text.contains("<!entity")) {
                throw new IOException("DOCTYPE/ENTITY declarations are not allowed");
            }
        }
    }


    public static void main(String[] args) throws Exception {
        StreamingReader.builder().open((new FileInputStream("poc.xlsx")));
    }
}
