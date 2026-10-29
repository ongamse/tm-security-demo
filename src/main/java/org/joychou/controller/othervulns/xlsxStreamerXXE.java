package org.joychou.controller.othervulns;

import com.monitorjbl.xlsx.StreamingReader;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.multipart.MultipartFile;

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Locale;


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

    private static final long MAX_UPLOAD_BYTES = 10L * 1024 * 1024;  // 10 MB


    @GetMapping("/upload")
    public String index() {
        return "xxe_upload"; // return xxe_upload.html page
    }


    @PostMapping("/readxlsx")
    @ResponseBody
    public ResponseEntity<String> xllx_streamer_xxe(MultipartFile file) {
        if (!isAcceptableXlsx(file)) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("invalid upload");
        }
        try (InputStream in = file.getInputStream()) {
            StreamingReader.builder().open(in);
            return ResponseEntity.ok("ok");
        } catch (Exception e) {
            // Generic failure: do not leak parser details to the client.
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("invalid upload");
        }
    }

    /**
     * Validate the upload before it reaches the xlsx parser: non-empty, .xlsx name,
     * size cap, and ZIP magic bytes ("PK").
     */
    private static boolean isAcceptableXlsx(MultipartFile file) {
        if (file == null || file.isEmpty() || file.getSize() > MAX_UPLOAD_BYTES) {
            return false;
        }
        String name = file.getOriginalFilename();
        if (name == null || !name.toLowerCase(Locale.ROOT).endsWith(".xlsx")) {
            return false;
        }
        try (InputStream in = new BufferedInputStream(file.getInputStream())) {
            return in.read() == 'P' && in.read() == 'K';
        } catch (IOException e) {
            return false;
        }
    }


    public static void main(String[] args) throws Exception {
        StreamingReader.builder().open((new FileInputStream("poc.xlsx")));
    }
}
