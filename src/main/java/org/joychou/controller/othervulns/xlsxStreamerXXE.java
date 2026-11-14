package org.joychou.controller.othervulns;

import com.monitorjbl.xlsx.StreamingReader;
import org.apache.poi.ss.usermodel.Workbook;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.multipart.MultipartFile;
import org.joychou.security.XmlSafe;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;


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

    private static final int MAX_XML_ENTRY_BYTES = 20 * 1024 * 1024;
    private static final long MAX_PACKAGE_BYTES = 100L * 1024 * 1024;

    @GetMapping("/upload")
    public String index() {
        return "xxe_upload"; // return xxe_upload.html page
    }


    @PostMapping("/readxlsx")
    public void xllx_streamer_xxe(MultipartFile file) throws IOException {
        byte[] content = file.getBytes();
        // The streamer only ever sees a package whose XML parts were scanned for
        // DOCTYPE/ENTITY and re-serialized from a hardened parser (XmlSafe).
        byte[] safePackage = sanitizeXmlParts(content);
        StreamingReader.builder().open(new ByteArrayInputStream(safePackage));
    }

    /**
     * Rebuild the xlsx package: every XML part is rejected if it carries a DOCTYPE/ENTITY
     * (raw byte scan) and is otherwise re-serialized from a hardened DOM parse, so the
     * third-party streamer never parses attacker-supplied DTD content with a default parser.
     */
    private static byte[] sanitizeXmlParts(byte[] content) throws IOException {
        ByteArrayOutputStream packaged = new ByteArrayOutputStream();
        try (ZipInputStream zis = new ZipInputStream(new ByteArrayInputStream(content));
             ZipOutputStream zos = new ZipOutputStream(packaged)) {
            ZipEntry entry;
            long total = 0;
            while ((entry = zis.getNextEntry()) != null) {
                String entryName = entry.getName();
                if (entryName.contains("..") || entryName.startsWith("/") || entryName.contains("\\")) {
                    throw new IOException("Rejected unsafe zip entry name in xlsx");
                }
                if (entry.isDirectory()) {
                    continue;
                }
                byte[] data = readBounded(zis);
                total += data.length;
                if (total > MAX_PACKAGE_BYTES) {
                    throw new IOException("xlsx package too large");
                }
                String name = entryName.toLowerCase();
                if (name.endsWith(".xml") || name.endsWith(".rels") || name.endsWith(".vml")) {
                    try {
                        data = XmlSafe.sanitizeXml(data);
                    } catch (IOException e) {
                        throw new IOException("Rejected unsafe or malformed XML part in xlsx: " + entryName, e);
                    }
                }
                zos.putNextEntry(new ZipEntry(entryName));
                zos.write(data);
                zos.closeEntry();
            }
        }
        return packaged.toByteArray();
    }

    private static byte[] readBounded(InputStream in) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        int n;
        while ((n = in.read(buf)) != -1) {
            if (out.size() + n > MAX_XML_ENTRY_BYTES) {
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
