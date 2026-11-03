package org.joychou.controller.othervulns;

import com.monitorjbl.xlsx.StreamingReader;
import org.apache.poi.ss.usermodel.Workbook;

import org.joychou.security.XmlSecurity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.multipart.MultipartFile;

import javax.servlet.http.HttpServletResponse;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.util.Locale;
import java.util.zip.ZipOutputStream;
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
    public void xllx_streamer_xxe(MultipartFile file, HttpServletResponse response) throws IOException {
        try {
            // Rebuild the package so the streaming reader only ever sees XML parts that were
            // gated and re-serialized by the hardened parser, never the uploaded XML bytes.
            byte[] rebuilt = rebuildPackage(file.getBytes());
            StreamingReader.builder().open(new ByteArrayInputStream(rebuilt));
        } catch (Exception e) {
            // Do not echo parser/exception details to the client.
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid xlsx");
        }
    }

    /**
     * Fail closed if any XML part of the OOXML package is not plain UTF-8/ASCII, contains a
     * DOCTYPE / ENTITY / XInclude / stylesheet construct, or is not well formed. Every XML part
     * is replaced by the canonical document re-serialized from the hardened parse; all other
     * entries are copied unchanged.
     */
    private static byte[] rebuildPackage(byte[] data) throws IOException {
        ByteArrayOutputStream result = new ByteArrayOutputStream();
        try (ZipInputStream zis = new ZipInputStream(new ByteArrayInputStream(data));
             ZipOutputStream zos = new ZipOutputStream(result)) {
            ZipEntry entry;
            long total = 0;
            while ((entry = zis.getNextEntry()) != null) {
                String entryName = entry.getName();
                if (entryName.contains("..") || entryName.startsWith("/") || entryName.contains("\\")) {
                    throw new IOException("illegal zip entry name");
                }
                String lower = entryName.toLowerCase(Locale.ROOT);
                if (entry.isDirectory()) {
                    continue;
                }
                byte[] part = readBounded(zis);
                total += part.length;
                if (total > MAX_XML_PART_BYTES) {
                    throw new IOException("package too large");
                }
                if (lower.endsWith(".xml") || lower.endsWith(".rels")) {
                    try {
                        part = XmlSecurity.canonicalize(part).getBytes(StandardCharsets.UTF_8);
                    } catch (Exception e) {
                        throw new IOException("unsafe XML in package part", e);
                    }
                }
                zos.putNextEntry(new ZipEntry(entryName));
                zos.write(part);
                zos.closeEntry();
            }
        }
        return result.toByteArray();
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
