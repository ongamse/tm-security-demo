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
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.SecureRandom;

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
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final String HEX_DIGITS = "0123456789abcdef";
    private final Logger logger = LoggerFactory.getLogger(this.getClass());

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
            Path path = resolveInUploadFolder(file.getOriginalFilename());
            Files.write(path, bytes);

            redirectAttributes.addFlashAttribute("message",
                    "You successfully uploaded '" + path + "'");

        } catch (IOException | IllegalArgumentException e) {
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
        if (fileName == null || fileName.lastIndexOf('.') < 0) {
            logger.error("[-] Suffix error: missing file suffix");
            return "Upload failed. Illeagl picture.";
        }
        String Suffix = fileName.substring(fileName.lastIndexOf(".")); // 获取文件后缀名
        String mimeType = multifile.getContentType(); // 获取MIME类型

        // 判断文件后缀名是否在白名单内  校验1 (must run before anything touches the filesystem)
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

        // Server-side generated names: the client supplied name is never used in a file path.
        String safeSuffix = Suffix.toLowerCase();
        String filePath = resolveInUploadFolder(newFileBaseName() + safeSuffix).toString();
        File excelFile = convert(multifile, safeSuffix);


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
                deleteFile(excelFile.getPath());
                return "Upload failed. Illeagl picture.";
            }
        }

        // 判断文件内容是否是图片 校验3
        boolean isImageFlag = isImage(excelFile);
        deleteFile(excelFile.getPath());

        if (!isImageFlag) {
            logger.error("[-] File is not Image");
            return "Upload failed. Illeagl picture.";
        }


        try {
            // Get the file and save it somewhere
            byte[] bytes = multifile.getBytes();
            Path path = resolveInUploadFolder(Paths.get(filePath).getFileName().toString());
            Files.write(path, bytes, StandardOpenOption.CREATE_NEW);
        } catch (IOException e) {
            logger.error(e.toString());
            deleteFile(filePath);
            return "Upload failed";
        }

        logger.info("[+] Safe file. Suffix: {}, MIME: {}", Suffix, mimeType);
        logger.info("[+] Successfully uploaded {}", filePath);
        return HtmlUtils.htmlEscape(String.format("You successfully uploaded '%s'", filePath));
    }

    /**
     * Generate an unpredictable base name (32 lowercase hex chars, 128 bits) for uploaded files.
     */
    private static String newFileBaseName() {
        byte[] bytes = new byte[16];
        RANDOM.nextBytes(bytes);
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(HEX_DIGITS.charAt((b >> 4) & 0x0f));
            sb.append(HEX_DIGITS.charAt(b & 0x0f));
        }
        return sb.toString();
    }

    /**
     * Resolve a file name inside UPLOADED_FOLDER. Only the last path segment of the given
     * name is used, and the result must stay inside UPLOADED_FOLDER.
     */
    private static Path resolveInUploadFolder(String name) {
        if (name == null) {
            throw new IllegalArgumentException("Missing file name");
        }
        String base = name.substring(Math.max(name.lastIndexOf('/'), name.lastIndexOf('\\')) + 1);
        if (base.isEmpty() || base.equals(".") || base.equals("..") || base.indexOf('\0') >= 0) {
            throw new IllegalArgumentException("Illegal file name");
        }
        Path root = Paths.get(UPLOADED_FOLDER).toAbsolutePath().normalize();
        Path resolved = root.resolve(base).normalize();
        if (!resolved.startsWith(root) || !root.equals(resolved.getParent())) {
            throw new IllegalArgumentException("Illegal file path");
        }
        return resolved;
    }

    private void deleteFile(String filePath) {
        File delFile;
        try {
            delFile = resolveInUploadFolder(Paths.get(filePath).getFileName().toString()).toFile();
        } catch (IllegalArgumentException e) {
            logger.info("Illegal file path, delete refused");
            return;
        }
        if(delFile.isFile() && delFile.exists()) {
            if (delFile.delete()) {
                logger.info("[+] " + filePath + " delete successfully!");
                return;
            }
        }
        logger.info(filePath + " delete failed!");
    }

    /**
     * 为了使用ImageIO.read()
     *
     * 不建议使用transferTo，因为原始的MultipartFile会被覆盖
     * https://stackoverflow.com/questions/24339990/how-to-convert-a-multipart-file-to-file
     */
    private File convert(MultipartFile multiFile, String suffix) throws Exception {
        // 随机生成一个同后缀名的文件 (suffix is already validated against the allowlist)
        File convFile = resolveInUploadFolder(newFileBaseName() + suffix).toFile();
        boolean ret = convFile.createNewFile();
        if (!ret) {
            throw new IOException("Temporary file already exists");
        }
        try (FileOutputStream fos = new FileOutputStream(convFile)) {
            fos.write(multiFile.getBytes());
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
