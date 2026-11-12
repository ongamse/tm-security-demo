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
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Locale;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;


/**
 * Desc:  xlsx-streamer xxe vuln code
 * Usage: xl/workbook.xml
 * Ref:   https://www.itread01.com/hkpcyyp.html
 * Fix:   uploads are size/extension checked and every zip entry is scanned for DTD/entity
 *        declarations before the stream reaches xlsx-streamer (a legitimate xlsx never has them).
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
        byte[] safeXlsx = readValidatedXlsx(file);
        StreamingReader.builder().open(new ByteArrayInputStream(safeXlsx));
    }

    private static final long MAX_UPLOAD_BYTES = 20L * 1024 * 1024;
    private static final long MAX_UNCOMPRESSED_BYTES = 100L * 1024 * 1024;

    @ResponseStatus(HttpStatus.BAD_REQUEST)
    static class InvalidXlsxException extends RuntimeException {
        InvalidXlsxException(String message) {
            super(message);
        }
    }

    /**
     * Returns the uploaded bytes only if the upload is a bounded .xlsx whose zip entries contain no
     * DOCTYPE / ENTITY declarations (the prerequisite of every XXE payload); otherwise rejects it.
     */
    private static byte[] readValidatedXlsx(MultipartFile file) throws IOException {
        if (file == null || file.isEmpty() || file.getSize() > MAX_UPLOAD_BYTES) {
            throw new InvalidXlsxException("invalid upload");
        }
        String name = file.getOriginalFilename();
        if (name == null || !name.toLowerCase(Locale.ROOT).endsWith(".xlsx")) {
            throw new InvalidXlsxException("only .xlsx is accepted");
        }

        byte[] bytes;
        try (InputStream in = file.getInputStream()) {
            bytes = readBounded(in, MAX_UPLOAD_BYTES);
        }

        long total = 0;
        try (ZipInputStream zip = new ZipInputStream(new ByteArrayInputStream(bytes))) {
            ZipEntry entry;
            boolean sawEntry = false;
            while ((entry = zip.getNextEntry()) != null) {
                sawEntry = true;
                if (entry.isDirectory()) {
                    continue;
                }
                byte[] content = readBounded(zip, MAX_UNCOMPRESSED_BYTES - total);
                total += content.length;
                if (containsDtdDeclaration(content)) {
                    throw new InvalidXlsxException("DTD/entity declarations are not allowed");
                }
            }
            if (!sawEntry) {
                throw new InvalidXlsxException("not a valid xlsx");
            }
        }
        return bytes;
    }

    private static byte[] readBounded(InputStream in, long limit) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        long read = 0;
        int n;
        while ((n = in.read(buf)) != -1) {
            read += n;
            if (read > limit) {
                throw new InvalidXlsxException("content too large");
            }
            out.write(buf, 0, n);
        }
        return out.toByteArray();
    }

    /**
     * Case-insensitive search for "<!DOCTYPE" / "<!ENTITY". NUL bytes are dropped first so the
     * check also covers UTF-16 encoded XML parts.
     */
    private static boolean containsDtdDeclaration(byte[] content) {
        StringBuilder sb = new StringBuilder(content.length);
        for (byte b : content) {
            if (b != 0) {
                sb.append((char) (b & 0xFF));
            }
        }
        String text = sb.toString().toLowerCase(Locale.ROOT);
        return text.contains("<!doctype") || text.contains("<!entity");
    }


    public static void main(String[] args) throws Exception {
        StreamingReader.builder().open((new FileInputStream("poc.xlsx")));
    }
}
