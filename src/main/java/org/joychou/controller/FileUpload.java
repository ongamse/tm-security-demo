package org.joychou.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.util.HtmlUtils;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.Locale;
import java.util.UUID;

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
    private static final String[] PIC_SUFFIX_LIST = {".jpg", ".png", ".jpeg", ".gif", ".bmp", ".ico"};

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
            // Get the file and save it somewhere
            byte[] bytes = file.getBytes();
            Path path = newUploadPath(allowedExtension(file.getOriginalFilename(), null));
            saveNew(path, bytes);

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

        String mimeType = multifile.getContentType(); // 获取MIME类型

        // 判断文件后缀名是否在白名单内  校验1
        // The returned suffix is always one of the constants in PIC_SUFFIX_LIST (or "").
        String Suffix = allowedExtension(multifile.getOriginalFilename(), PIC_SUFFIX_LIST);
        if (Suffix.isEmpty()) {
            logger.error("[-] Suffix error: suffix missing or not allowed");
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

        // 判断文件内容是否是图片 校验3 (validated in memory, nothing touches disk before it passes)
        byte[] bytes;
        try {
            bytes = multifile.getBytes();
            if (!isImage(bytes)) {
                logger.error("[-] File is not Image");
                return "Upload failed. Illeagl picture.";
            }
        } catch (IOException e) {
            logger.error(e.toString());
            return "Upload failed";
        }

        // Server-generated destination name; the client name only contributes an allowlisted suffix.
        String filePath;
        try {
            Path safePath = newUploadPath(Suffix);
            filePath = safePath.toString();
            saveNew(safePath, bytes);
        } catch (IOException e) {
            logger.error(e.toString());
            return "Upload failed";
        }

        logger.info("[+] Safe file. Suffix: {}, MIME: {}", Suffix, mimeType);
        logger.info("[+] Successfully uploaded {}", filePath);
        return String.format("You successfully uploaded '%s'", HtmlUtils.htmlEscape(filePath));
    }

    /**
     * Return the lower-cased suffix (including the dot) of an untrusted file name, or "" when it
     * is missing or not acceptable. With a non-null allowlist the suffix must be one of its
     * entries; otherwise it must be a short alphanumeric suffix. The result never contains
     * path separators, so it is safe to append to a server-generated name.
     */
    private static String allowedExtension(String originalName, String[] allowList) {
        if (originalName == null) {
            return "";
        }
        String name = originalName.replace('\\', '/');
        name = name.substring(name.lastIndexOf('/') + 1);
        int dotIndex = name.lastIndexOf('.');
        if (dotIndex < 0) {
            return "";
        }
        String suffix = name.substring(dotIndex).toLowerCase(Locale.ROOT);
        if (allowList != null) {
            for (String allowed : allowList) {
                if (allowed.equals(suffix)) {
                    return allowed;
                }
            }
            return "";
        }
        return suffix.matches("\\.[a-z0-9]{1,10}") ? suffix : "";
    }

    /**
     * Build a new destination inside UPLOADED_FOLDER. The file name is a random UUID
     * (SecureRandom based) plus a pre-sanitized suffix, never user input. The base directory is
     * resolved with toRealPath() and the result must be a direct child of it.
     */
    private static Path newUploadPath(String sanitizedSuffix) throws IOException {
        Path base = Paths.get(UPLOADED_FOLDER).toRealPath();
        Path resolved = base.resolve(UUID.randomUUID().toString() + sanitizedSuffix).normalize();
        if (!resolved.startsWith(base) || !base.equals(resolved.getParent())) {
            throw new IOException("Illegal file path");
        }
        return resolved;
    }

    /**
     * Create the file atomically (CREATE_NEW fails if anything, including a symlink, already
     * exists at the path), so there is no check-then-write window.
     */
    private static void saveNew(Path dest, byte[] bytes) throws IOException {
        Files.write(dest, bytes, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
    }

    /**
     * Check if the content is a picture.
     */
    private static boolean isImage(byte[] content) throws IOException {
        BufferedImage bi = ImageIO.read(new ByteArrayInputStream(content));
        return bi != null;
    }
}
