package org.joychou.controller.othervulns;

import org.apache.poi.openxml4j.opc.OPCPackage;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.multipart.MultipartFile;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;


/**
 * Desc:  xlsx reader (previously xlsx-streamer, replaced with POI for XXE safety)
 * Fix:   use POI XSSFWorkbook with OPCPackage (no external entity processing)
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
        InputStream is = null;
        OPCPackage pkg = null;
        try {
            is = file.getInputStream();
            pkg = OPCPackage.open(is);
            XSSFWorkbook workbook = new XSSFWorkbook(pkg);
        } catch (Exception e) {
            throw new IOException("Failed to process xlsx file", e);
        } finally {
            if (pkg != null) { try { pkg.close(); } catch (Exception ignored) {} }
            if (is != null) { is.close(); }
        }
    }


    public static void main(String[] args) throws Exception {
        InputStream is = null;
        OPCPackage pkg = null;
        try {
            is = new FileInputStream("poc.xlsx");
            pkg = OPCPackage.open(is);
            XSSFWorkbook workbook = new XSSFWorkbook(pkg);
        } finally {
            if (pkg != null) { try { pkg.close(); } catch (Exception ignored) {} }
            if (is != null) { is.close(); }
        }
    }
}
