package org.joychou.controller.othervulns;

import com.monitorjbl.xlsx.StreamingReader;
import org.apache.poi.ss.usermodel.Workbook;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.multipart.MultipartFile;

import javax.xml.XMLConstants;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;
import org.xml.sax.helpers.DefaultHandler;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;


/**
 * Desc:  xlsx-streamer xxe vuln code
 * Usage: xl/workbook.xml
 * Ref:   https://www.itread01.com/hkpcyyp.html
 * Fix:   update xlsx-streamer to 2.1.0 or above, and pre-validate XML with XXE-safe SAXParser
 *
 * @author JoyChou @2019-09-05
 */
@Controller
@RequestMapping("xlsx-streamer")
public class xlsxStreamerXXE {

    /**
     * Create a SAXParserFactory with XXE protections enabled.
     */
    private static SAXParserFactory createXXESafeParserFactory() throws Exception {
        SAXParserFactory factory = SAXParserFactory.newInstance();
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
        factory.setXIncludeAware(false);
        return factory;
    }

    /**
     * Pre-validate an InputStream with an XXE-safe SAX parser.
     * The stream bytes are buffered so they can be re-read by StreamingReader afterwards.
     */
    private static InputStream preValidateXML(InputStream rawStream) throws Exception {
        byte[] data = org.springframework.util.StreamUtils.copyToByteArray(rawStream);
        SAXParserFactory spf = createXXESafeParserFactory();
        SAXParser parser = spf.newSAXParser();
        // Parse with an empty handler — any XXE/DTD will throw an exception
        parser.parse(new ByteArrayInputStream(data), new DefaultHandler());
        return new ByteArrayInputStream(data);
    }

    @GetMapping("/upload")
    public String index() {
        return "xxe_upload"; // return xxe_upload.html page
    }


    @PostMapping("/readxlsx")
    @ResponseBody
    public String xllx_streamer_xxe(MultipartFile file) throws Exception {
        // Pre-validate the uploaded XML to reject XXE payloads before passing to StreamingReader
        InputStream safeStream = preValidateXML(file.getInputStream());
        StreamingReader.builder().open(safeStream);
        return "OK";
    }


    public static void main(String[] args) throws Exception {
        InputStream safeStream = preValidateXML(new FileInputStream("poc.xlsx"));
        StreamingReader.builder().open(safeStream);
    }
}
