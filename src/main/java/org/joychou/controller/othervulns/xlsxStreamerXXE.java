package org.joychou.controller.othervulns;

import com.monitorjbl.xlsx.StreamingReader;
import org.apache.poi.ss.usermodel.Workbook;

import org.joychou.util.SecureXml;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.multipart.MultipartFile;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.Charset;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
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

    private static final long MAX_UPLOAD_BYTES = 10L * 1024 * 1024;
    private static final long MAX_UNCOMPRESSED_BYTES = 100L * 1024 * 1024;
    private static final int MAX_ZIP_ENTRIES = 1000;
    private static final int MAX_PART_CHARS = 64 * 1024 * 1024;

    @GetMapping("/upload")
    public String index() {
        return "xxe_upload"; // return xxe_upload.html page
    }


    @PostMapping("/readxlsx")
    public void xllx_streamer_xxe(MultipartFile file) throws IOException {
        if (file == null || file.isEmpty() || file.getSize() > MAX_UPLOAD_BYTES) {
            throw new IOException("Rejected xlsx: missing or too large upload");
        }
        String originalName = file.getOriginalFilename();
        if (originalName == null || !originalName.toLowerCase().endsWith(".xlsx")) {
            throw new IOException("Rejected xlsx: only .xlsx files are accepted");
        }
        byte[] content = file.getBytes();
        if (content.length < 4 || content[0] != 'P' || content[1] != 'K' || content[2] != 3 || content[3] != 4) {
            throw new IOException("Rejected xlsx: not a ZIP package");
        }
        // The streaming reader only ever sees a package that this class rebuilt from validated parts.
        byte[] rebuilt = rebuildPackage(content);
        StreamingReader.builder().open(new ByteArrayInputStream(rebuilt));
    }

    /**
     * Rebuild the xlsx package: every XML part (.xml / .rels) is decoded, validated by the strict
     * whitelist scanner in {@link SecureXml#canonicalize(String, int)} (no DOCTYPE / ENTITY / PI /
     * unknown references) and written into a new zip as a canonical re-serialisation. Entry names are
     * rebuilt from a printable ASCII table. Non-XML parts (images, binary blobs) are not copied since
     * the streaming reader never parses them. The upload bytes themselves never reach the reader.
     */
    private static byte[] rebuildPackage(byte[] content) throws IOException {
        ByteArrayOutputStream packageOut = new ByteArrayOutputStream(content.length);
        long totalBytes = 0;
        try (ZipInputStream zis = new ZipInputStream(new ByteArrayInputStream(content));
             ZipOutputStream zos = new ZipOutputStream(packageOut)) {
            ZipEntry entry;
            int entries = 0;
            byte[] buf = new byte[8192];
            while ((entry = zis.getNextEntry()) != null) {
                if (++entries > MAX_ZIP_ENTRIES) {
                    throw new IOException("Rejected xlsx: too many entries");
                }
                String name = entry.getName();
                String lower = name.toLowerCase();
                if (entry.isDirectory() || !(lower.endsWith(".xml") || lower.endsWith(".rels"))) {
                    continue;
                }
                if (name.contains("..") || name.startsWith("/") || name.contains("\\")) {
                    throw new IOException("Rejected xlsx: unsafe entry name");
                }

                ByteArrayOutputStream part = new ByteArrayOutputStream();
                int n;
                while ((n = zis.read(buf)) != -1) {
                    totalBytes += n;
                    if (totalBytes > MAX_UNCOMPRESSED_BYTES) {
                        throw new IOException("Rejected xlsx: uncompressed content too large");
                    }
                    part.write(buf, 0, n);
                }

                String canonical = SecureXml.canonicalize(decode(part.toByteArray()), MAX_PART_CHARS);

                zos.putNextEntry(new ZipEntry(SecureXml.asciiCopy(name)));
                zos.write(canonical.getBytes(StandardCharsets.UTF_8));
                zos.closeEntry();
            }
        } catch (IllegalArgumentException | SecureXml.XmlRejectedException e) {
            throw new IOException("Rejected xlsx: unsafe or malformed XML content");
        }
        return packageOut.toByteArray();
    }

    /** Strict decode: UTF-16 when a BOM says so, otherwise UTF-8; malformed input is refused. */
    private static String decode(byte[] data) throws IOException {
        Charset charset = StandardCharsets.UTF_8;
        if (data.length >= 2 && ((data[0] == (byte) 0xFE && data[1] == (byte) 0xFF)
                || (data[0] == (byte) 0xFF && data[1] == (byte) 0xFE))) {
            charset = StandardCharsets.UTF_16;
        }
        try {
            return charset.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(data))
                    .toString();
        } catch (CharacterCodingException e) {
            throw new IOException("Rejected xlsx: unsafe or malformed XML content");
        }
    }


    public static void main(String[] args) throws Exception {
        StreamingReader.builder().open((new FileInputStream("poc.xlsx")));
    }
}
