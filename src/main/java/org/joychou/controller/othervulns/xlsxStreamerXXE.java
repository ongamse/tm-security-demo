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
import java.io.FileInputStream;
import java.io.IOException;


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

    private static final long MAX_UPLOAD_BYTES = 20L * 1024 * 1024;


    @GetMapping("/upload")
    public String index() {
        return "xxe_upload"; // return xxe_upload.html page
    }


    @PostMapping("/readxlsx")
    public void xllx_streamer_xxe(MultipartFile file) throws IOException {
        if (file.getSize() > MAX_UPLOAD_BYTES) {
            throw new IOException("Uploaded file is too large");
        }
        byte[] content = file.getBytes();
        // Zip entry count/size caps and every XML part (DOCTYPE/ENTITY rejected, hardened SAX
        // parser) are validated before the library sees the package.
        SecureXml.requireSafeXlsx(content);
        try (Workbook workbook = StreamingReader.builder().open(new ByteArrayInputStream(content))) {
            // package passed validation; nothing further to do with the workbook here
        }
    }

    public static void main(String[] args) throws Exception {
        StreamingReader.builder().open((new FileInputStream("poc.xlsx")));
    }
}
