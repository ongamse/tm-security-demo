package org.joychou.controller.othervulns;

import org.apache.poi.openxml4j.opc.OPCPackage;
import org.apache.poi.xssf.eventusermodel.XSSFReader;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.multipart.MultipartFile;

import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamReader;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Iterator;


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
    public void xllx_streamer_xxe(MultipartFile file) throws IOException {
        // Use OPCPackage + secure XMLInputFactory to prevent XXE
        try {
            OPCPackage pkg = OPCPackage.open(file.getInputStream());
            XSSFReader reader = new XSSFReader(pkg);
            XMLInputFactory xmlInputFactory = XMLInputFactory.newInstance();
            xmlInputFactory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
            xmlInputFactory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
            Iterator<InputStream> sheets = reader.getSheetsData();
            while (sheets.hasNext()) {
                try (InputStream sheet = sheets.next()) {
                    XMLStreamReader xmlReader = xmlInputFactory.createXMLStreamReader(sheet);
                    while (xmlReader.hasNext()) {
                        xmlReader.next();
                    }
                    xmlReader.close();
                }
            }
            pkg.close();
        } catch (Exception e) {
            throw new IOException("Failed to safely parse xlsx", e);
        }
    }


    public static void main(String[] args) throws Exception {
        // Use OPCPackage + secure XMLInputFactory to prevent XXE
        try {
            OPCPackage pkg = OPCPackage.open(new FileInputStream("poc.xlsx"));
            XSSFReader reader = new XSSFReader(pkg);
            XMLInputFactory xmlInputFactory = XMLInputFactory.newInstance();
            xmlInputFactory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
            xmlInputFactory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
            Iterator<InputStream> sheets = reader.getSheetsData();
            while (sheets.hasNext()) {
                try (InputStream sheet = sheets.next()) {
                    XMLStreamReader xmlReader = xmlInputFactory.createXMLStreamReader(sheet);
                    while (xmlReader.hasNext()) {
                        xmlReader.next();
                    }
                    xmlReader.close();
                }
            }
            pkg.close();
        } catch (Exception e) {
            throw new RuntimeException("Failed to safely parse xlsx", e);
        }
    }
}
