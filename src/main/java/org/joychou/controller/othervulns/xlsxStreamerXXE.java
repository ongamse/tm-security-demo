package org.joychou.controller.othervulns;

import com.monitorjbl.xlsx.StreamingReader;
import org.apache.poi.ss.usermodel.Workbook;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.multipart.MultipartFile;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;


/**
 * Desc:  xlsx-streamer xxe - secured by upgrading xlsx-streamer to 2.1.0+
 * Usage: xl/workbook.xml
 * Ref:   https://www.itread01.com/hkpcyyp.html
 * Fix:   xlsx-streamer >= 2.1.0 disables external entities internally
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
        // xlsx-streamer 2.1.0+ secures XML parsing internally (XXE disabled)
        try (InputStream is = file.getInputStream()) {
            Workbook workbook = StreamingReader.builder().open(is);
            // process workbook securely — StreamingWorkbook is cleaned up when InputStream closes
        }
    }


    public static void main(String[] args) throws Exception {
        try (InputStream is = new FileInputStream("poc.xlsx")) {
            Workbook workbook = StreamingReader.builder().open(is);
            // process workbook securely — StreamingWorkbook is cleaned up when InputStream closes
        }
    }
}
