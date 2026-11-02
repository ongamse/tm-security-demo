package org.joychou.controller.othervulns;

import com.monitorjbl.xlsx.StreamingReader;
import org.apache.poi.ss.usermodel.Workbook;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.multipart.MultipartFile;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.Locale;


/**
 * Desc:  xlsx-streamer xxe code (xl/workbook.xml)
 * Ref:   https://www.itread01.com/hkpcyyp.html
 * Fix:   xlsx-streamer updated to 2.1.0 (disables external entities when parsing workbook.xml)
 *
 * @author JoyChou @2019-09-05
 */
@Controller
@RequestMapping("xlsx-streamer")
public class xlsxStreamerXXE {

    private static final long MAX_XLSX_SIZE = 5L * 1024 * 1024; // 5 MB upload cap


    @GetMapping("/upload")
    public String index() {
        return "xxe_upload"; // return xxe_upload.html page
    }


    @PostMapping("/readxlsx")
    public void xllx_streamer_xxe(MultipartFile file) throws IOException {
        if (file == null || file.isEmpty() || file.getSize() > MAX_XLSX_SIZE) {
            throw new IllegalArgumentException("invalid xlsx upload size");
        }
        String name = file.getOriginalFilename();
        if (name == null || !name.toLowerCase(Locale.ROOT).endsWith(".xlsx")) {
            throw new IllegalArgumentException("only .xlsx files are accepted");
        }
        // Read the bounded upload and verify the ZIP magic header ("PK\3\4") before parsing.
        byte[] content = file.getBytes();
        if (content.length < 4 || content[0] != 'P' || content[1] != 'K' || content[2] != 3 || content[3] != 4) {
            throw new IllegalArgumentException("not a valid xlsx (zip) file");
        }
        // xlsx-streamer 2.1.0+ disables external entities when parsing workbook.xml.
        StreamingReader.builder().open(new ByteArrayInputStream(content));
    }


    public static void main(String[] args) throws Exception {
        StreamingReader.builder().open((new FileInputStream("poc.xlsx")));
    }
}
