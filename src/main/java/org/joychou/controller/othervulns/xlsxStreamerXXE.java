package org.joychou.controller.othervulns;

import org.apache.poi.openxml4j.opc.OPCPackage;
import org.apache.poi.xssf.eventusermodel.XSSFReader;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.multipart.MultipartFile;

import javax.xml.parsers.SAXParserFactory;
import java.io.FileInputStream;
import java.io.InputStream;
import java.util.Iterator;

import org.xml.sax.InputSource;
import org.xml.sax.XMLReader;
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
        // Use OPCPackage + XSSFReader with an XXE-safe SAXParserFactory
        SAXParserFactory spf = SAXParserFactory.newInstance();
        spf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        spf.setFeature("http://xml.org/sax/features/external-general-entities", false);
        spf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        spf.setFeature("http://javax.xml.XMLConstants/feature/secure-processing", true);
        spf.setNamespaceAware(true);

        OPCPackage pkg = OPCPackage.open(file.getInputStream());
        try {
            XSSFReader reader = new XSSFReader(pkg);
            XMLReader xmlReader = spf.newSAXParser().getXMLReader();
            xmlReader.setContentHandler(new DefaultHandler());

            Iterator<InputStream> sheets = reader.getSheetsData();
            while (sheets.hasNext()) {
                try (InputStream sheet = sheets.next()) {
                    xmlReader.parse(new InputSource(sheet));
                }
            }
        } finally {
            pkg.close();
        }
    }


    public static void main(String[] args) throws Exception {
        // Use OPCPackage + XSSFReader with an XXE-safe SAXParserFactory
        SAXParserFactory spf = SAXParserFactory.newInstance();
        spf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        spf.setFeature("http://xml.org/sax/features/external-general-entities", false);
        spf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        spf.setFeature("http://javax.xml.XMLConstants/feature/secure-processing", true);
        spf.setNamespaceAware(true);

        OPCPackage pkg = OPCPackage.open(new FileInputStream("poc.xlsx"));
        try {
            XSSFReader reader = new XSSFReader(pkg);
            XMLReader xmlReader = spf.newSAXParser().getXMLReader();
            xmlReader.setContentHandler(new DefaultHandler());

            Iterator<InputStream> sheets = reader.getSheetsData();
            while (sheets.hasNext()) {
                try (InputStream sheet = sheets.next()) {
                    xmlReader.parse(new InputSource(sheet));
                }
            }
        } finally {
            pkg.close();
        }
    }
}
