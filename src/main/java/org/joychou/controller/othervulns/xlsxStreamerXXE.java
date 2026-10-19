package org.joychou.controller.othervulns;

import com.monitorjbl.xlsx.StreamingReader;
import org.apache.poi.ss.usermodel.Workbook;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.multipart.MultipartFile;

import java.io.FileInputStream;
import java.io.InputStream;

import javax.xml.XMLConstants;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;

import org.apache.poi.openxml4j.opc.OPCPackage;
import org.apache.poi.openxml4j.opc.PackagePart;
import org.xml.sax.helpers.DefaultHandler;


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


    @GetMapping("/upload")
    public String index() {
        return "xxe_upload"; // return xxe_upload.html page
    }


    @PostMapping("/readxlsx")
    public void xllx_streamer_xxe(MultipartFile file) throws Exception {
        OPCPackage pkg = OPCPackage.open(file.getInputStream());
        validateNoXXE(pkg);
        StreamingReader.builder().open(pkg);
    }


    public static void main(String[] args) throws Exception {
        OPCPackage pkg = OPCPackage.open(new FileInputStream("poc.xlsx"));
        validateNoXXE(pkg);
        StreamingReader.builder().open(pkg);
    }

    /**
     * Validates every XML part inside the OPCPackage using a SAX parser with
     * external entities and DTDs disabled. Throws an exception if any part
     * contains a DTD or external entity reference.
     */
    private static void validateNoXXE(OPCPackage pkg) throws Exception {
        SAXParserFactory spf = SAXParserFactory.newInstance();
        spf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        spf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        spf.setFeature("http://xml.org/sax/features/external-general-entities", false);
        spf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        SAXParser parser = spf.newSAXParser();

        for (PackagePart part : pkg.getParts()) {
            String contentType = part.getContentType();
            if (contentType != null && contentType.contains("xml")) {
                try (InputStream is = part.getInputStream()) {
                    parser.parse(is, new DefaultHandler());
                }
            }
        }
    }
}
