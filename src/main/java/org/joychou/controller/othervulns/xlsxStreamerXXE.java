package org.joychou.controller.othervulns;

import com.monitorjbl.xlsx.StreamingReader;
import org.apache.poi.ss.usermodel.Workbook;

import org.joychou.util.SecureXml;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.multipart.MultipartFile;

import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.helpers.DefaultHandler;

import javax.xml.parsers.ParserConfigurationException;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
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

    private static final long MAX_UPLOAD_BYTES = 10L * 1024 * 1024;
    private static final long MAX_UNCOMPRESSED_BYTES = 100L * 1024 * 1024;
    private static final int MAX_ZIP_ENTRIES = 1000;

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
        rejectXmlEntities(content);
        StreamingReader.builder().open(new ByteArrayInputStream(content));
    }

    /**
     * Pre-scan every XML part of the xlsx package with a per-instance hardened parser
     * (SecureXml: DOCTYPE disallowed, no external entities/DTDs, empty entity resolver) and reject
     * the file if any part declares a DOCTYPE / ENTITY, before it reaches the streaming reader.
     * No JVM-wide System properties are used.
     */
    private static void rejectXmlEntities(byte[] content) throws IOException {
        try {
            long totalBytes = 0;
            try (ZipInputStream zis = new ZipInputStream(new ByteArrayInputStream(content))) {
                ZipEntry entry;
                int entries = 0;
                while ((entry = zis.getNextEntry()) != null) {
                    if (++entries > MAX_ZIP_ENTRIES) {
                        throw new IOException("Rejected xlsx: too many entries");
                    }
                    String name = entry.getName().toLowerCase();
                    if (entry.isDirectory() || !(name.endsWith(".xml") || name.endsWith(".rels"))) {
                        continue;
                    }
                    final long remaining = MAX_UNCOMPRESSED_BYTES - totalBytes;
                    final long[] read = {0};
                    InputStream partStream = new FilterInputStream(zis) {
                        @Override
                        public int read() throws IOException {
                            int b = super.read();
                            if (b != -1 && ++read[0] > remaining) {
                                throw new IOException("Rejected xlsx: uncompressed content too large");
                            }
                            return b;
                        }

                        @Override
                        public int read(byte[] buf, int off, int len) throws IOException {
                            int n = super.read(buf, off, len);
                            if (n > 0) {
                                read[0] += n;
                                if (read[0] > remaining) {
                                    throw new IOException("Rejected xlsx: uncompressed content too large");
                                }
                            }
                            return n;
                        }

                        @Override
                        public void close() {
                            // keep the zip stream open for the next entry
                        }
                    };
                    SecureXml.newSaxParser().parse(new InputSource(partStream), new DefaultHandler());
                    totalBytes += read[0];
                }
            }
        } catch (ParserConfigurationException | SAXException e) {
            throw new IOException("Rejected xlsx: unsafe or malformed XML content", e);
        }
    }


    public static void main(String[] args) throws Exception {
        StreamingReader.builder().open((new FileInputStream("poc.xlsx")));
    }
}
