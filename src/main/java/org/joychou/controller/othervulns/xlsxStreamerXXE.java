package org.joychou.controller.othervulns;

import com.monitorjbl.xlsx.StreamingReader;
import org.joychou.security.XmlSafe;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.multipart.MultipartFile;

import java.io.ByteArrayInputStream;
import java.io.IOException;


/**
 * Desc:  xlsx-streamer xxe code
 * Usage: xl/workbook.xml
 * Ref:   https://www.itread01.com/hkpcyyp.html
 * Fix:   uploads are validated (size cap, ZIP magic, no DOCTYPE/ENTITY in any XML part) before they reach
 *        the streaming reader; rejected uploads return HTTP 400 without echoing any content.
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
        if (file == null || file.isEmpty()) {
            throw new XmlSafe.RejectedXmlException();
        }
        byte[] validated = XmlSafe.validateOoxmlUpload(file.getInputStream());
        StreamingReader.builder().open(new ByteArrayInputStream(validated));
    }
}
