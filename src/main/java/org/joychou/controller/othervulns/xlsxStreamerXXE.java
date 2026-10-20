package org.joychou.controller.othervulns;

import com.monitorjbl.xlsx.StreamingReader;
import org.apache.poi.openxml4j.opc.OPCPackage;
import org.apache.poi.ss.usermodel.Workbook;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.multipart.MultipartFile;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;


@Controller
@RequestMapping("xlsx-streamer")
public class xlsxStreamerXXE {


    @GetMapping("/upload")
    public String index() {
        return "xxe_upload"; // return xxe_upload.html page
    }

    private void validateNoXXE(InputStream is) throws IOException {
        ZipInputStream zis = new ZipInputStream(is);
        ZipEntry entry;
        byte[] buf = new byte[4096];
        while ((entry = zis.getNextEntry()) != null) {
            if (entry.getName().endsWith(".xml") || entry.getName().endsWith(".rels")) {
                StringBuilder sb = new StringBuilder();
                int len;
                while ((len = zis.read(buf)) > 0) {
                    sb.append(new String(buf, 0, len, "UTF-8"));
                }
                String content = sb.toString();
                if (content.contains("<!DOCTYPE") || content.contains("<!ENTITY")
                        || content.contains("SYSTEM") || content.contains("PUBLIC")) {
                    throw new IOException("Rejected: XML content contains potentially dangerous DTD/entity declarations");
                }
            }
        }
    }

    @PostMapping("/readxlsx")
    public void xllx_streamer_xxe(MultipartFile file) throws IOException {
        validateNoXXE(file.getInputStream());
        StreamingReader.builder().open(file.getInputStream());
    }


    public static void main(String[] args) throws Exception {
        StreamingReader.builder().open((new FileInputStream("poc.xlsx")));
    }
}
