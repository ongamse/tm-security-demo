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
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.Locale;

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
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private static final int NAME_RANDOM_BYTES = 16;
    private static final char[] HEX_DIGITS = "0123456789abcdef".toCharArray();
    private final Logger logger = LoggerFactory.getLogger(this.getClass());
    private static final String[] PIC_SUFFIX_LIST = {".jpg", ".png", ".jpeg", ".gif", ".bmp", ".ico"};
    private static final String[] ANY_SUFFIX_LIST = {".jpg", ".png", ".jpeg", ".gif", ".bmp", ".ico",
            ".txt", ".pdf", ".csv", ".zip", ".doc", ".docx", ".xls", ".xlsx"};

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
            // Get the file and save it somewhere under a server-generated name
            byte[] bytes = file.getBytes();
            String storedName = generateStoredName(pickExtension(file.getOriginalFilename(), ANY_SUFFIX_LIST, ".bin"));
            Path path = resolveUploadPath(storedName);
            Files.write(path, bytes);

            redirectAttributes.addFlashAttribute("message",
                    "You successfully uploaded '" + UPLOADED_FOLDER + storedName + "'");

        } catch (IOException e) {
            redirectAttributes.addFlashAttribute("message", "upload failed");
            logger.error("File upload failed: {}", e.getClass().getSimpleName());
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
        // The stored suffix is always a constant taken from the allowlist, never the client string.
        String suffix = pickExtension(multifile.getOriginalFilename(), PIC_SUFFIX_LIST, null);
        if (suffix == null) {
            logger.error("[-] Suffix error");
            return "Upload failed. Illeagl picture.";
        }

        Path safePath;
        try {
            safePath = resolveUploadPath(generateStoredName(suffix));
        } catch (IOException e) {
            logger.error("[-] Illegal file name");
            return "Upload failed. Illeagl picture.";
        }
        String filePath = safePath.toString();
        File excelFile = convert(multifile, suffix);

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
                logger.error("[-] Mime type error");
                deleteFile(excelFile);
                return "Upload failed. Illeagl picture.";
            }
        }

        // 判断文件内容是否是图片 校验3
        boolean isImageFlag = isImage(excelFile);
        deleteFile(excelFile);

        if (!isImageFlag) {
            logger.error("[-] File is not Image");
            return "Upload failed. Illeagl picture.";
        }


        try {
            // Get the file and save it somewhere
            byte[] bytes = multifile.getBytes();
            Files.write(safePath, bytes);
        } catch (IOException e) {
            logger.error("[-] Saving picture failed: {}", e.getClass().getSimpleName());
            deleteFile(safePath.toFile());
            return "Upload failed";
        }

        logger.info("[+] Safe file uploaded successfully");
        return HtmlUtils.htmlEscape(String.format("You successfully uploaded '%s'", filePath));
    }

    /**
     * Return the allowlisted suffix (the constant from the list, lower case) that matches the
     * extension of the client supplied name, or the fallback when none matches. The client
     * string itself is never returned.
     */
    private static String pickExtension(String originalName, String[] allowed, String fallback) {
        if (originalName == null) {
            return fallback;
        }
        int idx = originalName.lastIndexOf('.');
        if (idx < 0) {
            return fallback;
        }
        String ext = originalName.substring(idx).toLowerCase(Locale.ROOT);
        for (String candidate : allowed) {
            if (candidate.equals(ext)) {
                return candidate;
            }
        }
        return fallback;
    }

    /**
     * Server-generated file name: 16 random bytes from SecureRandom (hex encoded) plus an
     * allowlisted suffix.
     */
    private static String generateStoredName(String allowedSuffix) {
        byte[] random = new byte[NAME_RANDOM_BYTES];
        SECURE_RANDOM.nextBytes(random);
        StringBuilder sb = new StringBuilder(NAME_RANDOM_BYTES * 2 + allowedSuffix.length());
        for (byte b : random) {
            sb.append(HEX_DIGITS[(b >> 4) & 0x0f]).append(HEX_DIGITS[b & 0x0f]);
        }
        return sb.append(allowedSuffix).toString();
    }

    /**
     * Resolve a server-generated file name against the upload folder and make sure the result is
     * a direct child of it.
     */
    private static Path resolveUploadPath(String generatedName) throws IOException {
        if (generatedName == null || generatedName.isEmpty()) {
            throw new IOException("Invalid file name");
        }
        Path base = Paths.get(UPLOADED_FOLDER).toAbsolutePath().normalize();
        Path resolved;
        try {
            resolved = base.resolve(generatedName).normalize();
        } catch (InvalidPathException e) {
            throw new IOException("Invalid file name", e);
        }
        if (!base.equals(resolved.getParent())) {
            throw new IOException("File path escapes upload folder");
        }
        return resolved;
    }

    private void deleteFile(File delFile) {
        if (delFile == null) {
            return;
        }
        try {
            Files.deleteIfExists(delFile.toPath());
        } catch (IOException e) {
            logger.info("Temporary file delete failed");
        }
    }

    /**
     * 为了使用ImageIO.read()
     *
     * 不建议使用transferTo，因为原始的MultipartFile会被覆盖
     * https://stackoverflow.com/questions/24339990/how-to-convert-a-multipart-file-to-file
     */
    private File convert(MultipartFile multiFile, String allowedSuffix) throws Exception {
        // 随机生成一个同后缀名的文件 (suffix is an allowlisted constant)
        Path convPath = resolveUploadPath(generateStoredName(allowedSuffix));
        File convFile = convPath.toFile();
        if (!convFile.createNewFile()) {
            throw new IOException("Could not create temporary file");
        }
        FileOutputStream fos = new FileOutputStream(convFile);
        try {
            fos.write(multiFile.getBytes());
        } finally {
            fos.close();
        }
        return convFile;
    }

    /**
     * Check if the file is a picture.
     */
    private static boolean isImage(File file) throws IOException {
        BufferedImage bi = ImageIO.read(file);
        return bi != null;
    }
}
