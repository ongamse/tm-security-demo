package org.joychou.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.UUID;

import static org.joychou.security.SecurityUtil.sanitizeLogParam;
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
    private static String randomFilePath = "";

    /**
     * Sanitize a user-supplied filename: strip directory components and reject traversal sequences.
     */
    private static String sanitizeFileName(String originalFilename) {
        if (originalFilename == null || originalFilename.isEmpty()) {
            return null;
        }
        // Extract just the filename, stripping any directory components
        String name = Paths.get(originalFilename).getFileName().toString();
        if (name.isEmpty() || name.contains("..")) {
            return null;
        }
        return name;
    }

    /**
     * Resolve a filename under a base directory and verify the result stays within bounds.
     */
    private static Path safePath(String baseDir, String fileName) throws IOException {
        Path base = Paths.get(baseDir).toAbsolutePath().normalize();
        Path resolved = base.resolve(fileName).normalize();
        if (!resolved.startsWith(base)) {
            throw new IOException("Path traversal attempt detected");
        }
        return resolved;
    }

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
            String safeName = sanitizeFileName(file.getOriginalFilename());
            if (safeName == null) {
                redirectAttributes.addFlashAttribute("message", "Invalid file name");
                return "redirect:/file/status";
            }
            byte[] bytes = file.getBytes();
            Path path = safePath(UPLOADED_FOLDER, safeName);
            Files.write(path, bytes);

            redirectAttributes.addFlashAttribute("message",
                    "You successfully uploaded '" + path.toString() + "'");

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

        String rawFileName = multifile.getOriginalFilename();
        String fileName = sanitizeFileName(rawFileName);
        if (fileName == null) {
            return "Upload failed. Invalid file name.";
        }
        String Suffix = fileName.substring(fileName.lastIndexOf(".")); // 获取文件后缀名
        String mimeType = multifile.getContentType(); // 获取MIME类型
        Path safeFilePath;
        try {
            safeFilePath = safePath(UPLOADED_FOLDER, fileName);
        } catch (IOException e) {
            return "Upload failed. Invalid file path.";
        }
        String filePath = safeFilePath.toString();
        File excelFile = convert(multifile);


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
            logger.error("[-] Suffix error: " + sanitizeLogParam(Suffix));
            deleteFile(filePath);
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
                logger.error("[-] Mime type error: " + sanitizeLogParam(mimeType));
                deleteFile(filePath);
                return "Upload failed. Illeagl picture.";
            }
        }

        // 判断文件内容是否是图片 校验3
        boolean isImageFlag = isImage(excelFile);
        deleteFile(randomFilePath);

        if (!isImageFlag) {
            logger.error("[-] File is not Image");
            deleteFile(filePath);
            return "Upload failed. Illeagl picture.";
        }


        try {
            // Get the file and save it somewhere
            byte[] bytes = multifile.getBytes();
            Files.write(safeFilePath, bytes);
        } catch (IOException e) {
            logger.error(e.toString());
            deleteFile(filePath);
            return "Upload failed";
        }

        logger.info("[+] Safe file. Suffix: {}, MIME: {}", sanitizeLogParam(Suffix), sanitizeLogParam(mimeType));
        logger.info("[+] Successfully uploaded {}", sanitizeLogParam(filePath));
        return String.format("You successfully uploaded '%s'", filePath);
    }

    private void deleteFile(String filePath) {
        Path delPath = Paths.get(filePath).toAbsolutePath().normalize();
        Path allowedBase = Paths.get(UPLOADED_FOLDER).toAbsolutePath().normalize();
        if (!delPath.startsWith(allowedBase)) {
            logger.error("Refusing to delete file outside upload directory: " + sanitizeLogParam(filePath));
            return;
        }
        try {
            if (Files.deleteIfExists(delPath)) {
                logger.info("[+] " + sanitizeLogParam(filePath) + " delete successfully!");
            } else {
                logger.info(filePath + " does not exist.");
            }
        } catch (IOException e) {
            logger.info(sanitizeLogParam(filePath) + " delete failed!");
        }
    }

    /**
     * 为了使用ImageIO.read()
     *
     * 不建议使用transferTo，因为原始的MultipartFile会被覆盖
     * https://stackoverflow.com/questions/24339990/how-to-convert-a-multipart-file-to-file
     */
    private File convert(MultipartFile multiFile) throws Exception {
        String rawName = multiFile.getOriginalFilename();
        String safeName = sanitizeFileName(rawName);
        if (safeName == null || !safeName.contains(".")) {
            throw new Exception("Invalid file name");
        }
        String suffix = safeName.substring(safeName.lastIndexOf("."));
        UUID uuid = UUID.randomUUID();
        Path safeRandomPath = safePath(UPLOADED_FOLDER, uuid + suffix);
        randomFilePath = safeRandomPath.toString();
        // Atomically create the file and write content
        Files.createFile(safeRandomPath);
        try (OutputStream fos = Files.newOutputStream(safeRandomPath, StandardOpenOption.WRITE)) {
            fos.write(multiFile.getBytes());
        }
        return safeRandomPath.toFile();
    }

    /**
     * Check if the file is a picture.
     */
    private static boolean isImage(File file) throws IOException {
        Path filePath = file.toPath().toAbsolutePath().normalize();
        Path allowedBase = Paths.get(UPLOADED_FOLDER).toAbsolutePath().normalize();
        if (!filePath.startsWith(allowedBase)) {
            throw new IOException("File is outside the allowed upload directory");
        }
        BufferedImage bi = ImageIO.read(file);
        return bi != null;
    }
}
