package org.joychou.controller;

import org.springframework.web.util.HtmlUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.SecureRandom;
import java.util.regex.Pattern;

import org.joychou.security.SecurityUtil;


/**
 * File upload.
 *
 * @author JoyChou @ 2018-08-15
 */
@Controller
@RequestMapping("/file")
public class FileUpload {

    // Save the uploaded file to this folder
    private static final String UPLOADED_FOLDER = "/tmp/";
    private final Logger logger = LoggerFactory.getLogger(this.getClass());
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private static final Pattern SAFE_SUFFIX =Pattern.compile("^(\\.[A-Za-z0-9]{1,10})?$");

    // uplaod any file
    @GetMapping("/any")
    public String index() {
        return "upload"; // return upload.html page
    }

    // only allow to upload pictures
    @GetMapping("/pic")
    public String uploadPic() {
        return "uploadPic"; // return uploadPic.html page
    }

    @PostMapping("/upload")
    public String singleFileUpload(@RequestParam("file") MultipartFile file,
                                   RedirectAttributes redirectAttributes) {
        if (file.isEmpty()) {
            // 赋值给uploadStatus.html里的动态参数message
            redirectAttributes.addFlashAttribute("message", "Please select a file to upload");
            return "redirect:/file/status";
        }

        try {
            // Get the file and save it somewhere. The file name is server generated.
            byte[] bytes = file.getBytes();
            Path path = newUploadPath(extensionOf(file.getOriginalFilename()));
            Files.write(path, bytes, StandardOpenOption.CREATE_NEW);

            redirectAttributes.addFlashAttribute("message",
                    "You successfully uploaded '" + path + "'");

        } catch (IOException e) {
            redirectAttributes.addFlashAttribute("message", "upload failed");
            logger.error(e.toString());
        }

        return "redirect:/file/status";
    }

    @GetMapping("/status")
    public String uploadStatus() {
        return "uploadStatus";
    }

    // only upload picture
    @PostMapping("/upload/picture")
    @ResponseBody
    public String uploadPicture(@RequestParam("file") MultipartFile multifile) throws Exception {
        if (multifile.isEmpty()) {
            return "Please select a file to upload";
        }

        String fileName = multifile.getOriginalFilename();
        String Suffix = extensionOf(fileName); // 获取文件后缀名 (empty when missing or unsafe)
        String mimeType = multifile.getContentType(); // 获取MIME类型

        // 判断文件后缀名是否在白名单内  校验1
        String[] picSuffixList = {".jpg", ".png", ".jpeg", ".gif", ".bmp", ".ico"};
        boolean suffixFlag = false;
        for (String white_suffix : picSuffixList) {
            if (Suffix.toLowerCase().equals(white_suffix)) {
                suffixFlag = true;
                break;
            }
        }
        if (!suffixFlag) {
            logger.error("[-] Suffix error: " + Suffix);
            return "Upload failed. Illeagl picture.";
        }

        // 判断MIME类型是否在黑名单内 校验2
        String[] mimeTypeBlackList = {
                "text/html",
                "text/javascript",
                "application/javascript",
                "application/ecmascript",
                "text/xml",
                "application/xml"
        };
        for (String blackMimeType : mimeTypeBlackList) {
            // 用contains是为了防止text/html;charset=UTF-8绕过
            if (SecurityUtil.replaceSpecialStr(mimeType).toLowerCase().contains(blackMimeType)) {
                logger.error("[-] Mime type error: " + mimeType);
                return "Upload failed. Illeagl picture.";
            }
        }

        // 判断文件内容是否是图片 校验3
        byte[] bytes = multifile.getBytes();
        if (!isImage(bytes)) {
            logger.error("[-] File is not Image");
            return "Upload failed. Illeagl picture.";
        }

        // The stored file name is server generated (SecureRandom hex + allowlisted suffix).
        Path path;
        try {
            path = newUploadPath(Suffix);
            Files.write(path, bytes, StandardOpenOption.CREATE_NEW);
        } catch (IOException e) {
            logger.error(e.toString());
            return "Upload failed";
        }
        String filePath = path.toString();

        logger.info("[+] Safe file. Suffix: {}, MIME: {}", Suffix, mimeType);
        logger.info("[+] Successfully uploaded {}", filePath);
        return String.format("You successfully uploaded '%s'", HtmlUtils.htmlEscape(filePath));
    }

    /**
     * Extract a safe file extension (including the dot) from a client supplied file name.
     * Returns an empty string when there is none or it is not a short alphanumeric suffix.
     * Only the extension is ever taken from client input, never any path component.
     */
    private static String extensionOf(String originalName) {
        if (originalName == null) {
            return "";
        }
        int idx = originalName.lastIndexOf('.');
        if (idx < 0) {
            return "";
        }
        String ext = originalName.substring(idx);
        return SAFE_SUFFIX.matcher(ext).matches() ? ext : "";
    }

    /**
     * Unpredictable file name: 16 bytes from SecureRandom, hex encoded (32 chars).
     */
    private static String randomName() {
        byte[] buf = new byte[16];
        SECURE_RANDOM.nextBytes(buf);
        StringBuilder sb = new StringBuilder(buf.length * 2);
        for (byte b : buf) {
            sb.append(Character.forDigit((b >> 4) & 0xF, 16));
            sb.append(Character.forDigit(b & 0xF, 16));
        }
        return sb.toString();
    }

    /**
     * Build a path inside the upload folder from a server generated name only
     * (SecureRandom hex + allowlisted extension) and verify containment before returning it.
     */
    private static Path newUploadPath(String safeSuffix) throws IOException {
        String suffix = SAFE_SUFFIX.matcher(safeSuffix).matches() ? safeSuffix : "";
        Path root = Paths.get(UPLOADED_FOLDER).toRealPath();
        Path resolved = root.resolve(randomName() + suffix).normalize();
        if (!resolved.startsWith(root) || !root.equals(resolved.getParent())) {
            throw new IOException("Illegal file path");
        }
        return resolved;
    }

    /**
     * Check if the content is a picture. Works on in-memory bytes so no file is opened.
     */
    private static boolean isImage(byte[] content) throws IOException {
        try (InputStream in = new ByteArrayInputStream(content)) {
            BufferedImage bi = ImageIO.read(in);
            return bi != null;
        }
    }
}
