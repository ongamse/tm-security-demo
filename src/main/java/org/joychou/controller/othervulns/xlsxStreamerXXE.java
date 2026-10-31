package org.joychou.controller.othervulns;

import com.monitorjbl.xlsx.StreamingReader;

import org.joychou.util.SecureXml;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.multipart.MultipartFile;

import java.io.FileInputStream;
import java.io.IOException;


/**
 * Desc:  xlsx-streamer xxe vuln code (remediated)
 * Usage: xl/workbook.xml
 * Ref:   https://www.itread01.com/hkpcyyp.html
 * Fix:   uploaded workbooks are never handed to xlsx-streamer / POI; the package is read with the
 *        hardened SAX parser in {@link SecureXml} (DOCTYPE and external entities disabled).
 *
 * @author JoyChou @2019-09-05
 */
@Controller
@RequestMapping("xlsx-streamer")
public class xlsxStreamerXXE {

    private static final Logger logger = LoggerFactory.getLogger(xlsxStreamerXXE.class);

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
        // Zip entry count/size caps are enforced and every XML part is parsed by the hardened SAX
        // parser (DOCTYPE/ENTITY rejected); worksheet rows/cells are counted in that same pass.
        long[] summary = SecureXml.summarizeXlsx(content);
        logger.info("xlsx upload read: {} rows, {} cells", summary[0], summary[1]);
    }

    public static void main(String[] args) throws Exception {
        StreamingReader.builder().open((new FileInputStream("poc.xlsx")));
    }
}
