package org.joychou.controller;

import com.fasterxml.uuid.Generators;
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
    private static final Path UPLOADED_BASE_DIR = Paths.get(UPLOADED_FOLDER).toAbsolutePath().normalize();
    private final Logger logger = LoggerFactory.getLogger(this.getClass());
    private static String randomFilePath = "";

    /**
     * Sanitize an uploaded filename: strip directory components and reject path traversal sequences.
     */
    private static String sanitizeFilename(String original) {
        if (original == null || original.isEmpty()) {
            return null;
        }
        // Strip any directory separators to keep only the base filename
        String name = Paths.get(original).getFileName().toString();
        // Reject path traversal sequences
        if (name.contains("..") || name.contains("/") || name.contains("\\") || name.isEmpty()) {
            return null;
        }
        return name;
    }

    /**
     * Resolve a filename against the upload base directory, ensuring no path traversal.
     * Returns null if the resolved path escapes the base directory.
     */
    private static Path safeResolve(String filename) {
        if (filename == null) {
            return null;
        }
        Path resolved = UPLOADED_BASE_DIR.resolve(filename).normalize();
        if (!resolved.startsWith(UPLOADED_BASE_DIR)) {
            return null;
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
            String safeName = sanitizeFilename(file.getOriginalFilename());
            if (safeName == null) {
                redirectAttributes.addFlashAttribute("message", "Invalid file name");
                return "redirect:/file/status";
            }
            Path safePath = safeResolve(safeName);
            if (safePath == null) {
                redirectAttributes.addFlashAttribute("message", "Invalid file path");
                return "redirect:/file/status";
            }

            // Get the file and save it somewhere
            byte[] bytes = file.getBytes();
            Files.write(safePath, bytes);

            redirectAttributes.addFlashAttribute("message",
                    "You successfully uploaded '" + safePath.toString() + "'");

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

        String safeName = sanitizeFilename(multifile.getOriginalFilename());
        if (safeName == null) {
            return "Upload failed. Invalid file name.";
        }
        Path safePath = safeResolve(safeName);
        if (safePath == null) {
            return "Upload failed. Invalid file path.";
        }

        String fileName = safeName;
        String Suffix = fileName.substring(fileName.lastIndexOf(".")); // 获取文件后缀名
        String mimeType = multifile.getContentType(); // 获取MIME类型
        String filePath = safePath.toString();
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
            logger.error("[-] Suffix error: " + Suffix);
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
                logger.error("[-] Mime type error: " + mimeType);
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
            Files.write(safePath, bytes);
        } catch (IOException e) {
            logger.error(e.toString());
            deleteFile(filePath);
            return "Upload failed";
        }

        logger.info("[+] Safe file. Suffix: {}, MIME: {}", Suffix, mimeType);
        logger.info("[+] Successfully uploaded {}", filePath);
        return String.format("You successfully uploaded '%s'", filePath);
    }

    private void deleteFile(String filePath) {
        // Validate the path stays within the upload directory before deleting
        Path resolved = Paths.get(filePath).toAbsolutePath().normalize();
        if (!resolved.startsWith(UPLOADED_BASE_DIR)) {
            logger.warn("Blocked attempt to delete file outside upload directory: " + filePath);
            return;
        }
        File delFile = resolved.toFile();
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
    private File convert(MultipartFile multiFile) throws Exception {
        String originalName = multiFile.getOriginalFilename();
        String safeName = sanitizeFilename(originalName);
        if (safeName == null) {
            throw new IllegalArgumentException("Invalid filename");
        }
        String suffix = safeName.substring(safeName.lastIndexOf("."));
        UUID uuid = Generators.timeBasedGenerator().generate();
        String randomName = uuid + suffix;
        Path safePath = safeResolve(randomName);
        if (safePath == null) {
            throw new IllegalArgumentException("Invalid file path for converted file");
        }
        randomFilePath = safePath.toString();
        // 随机生成一个同后缀名的文件
        File convFile = safePath.toFile();
        boolean ret = convFile.createNewFile();
        if (!ret) {
            return null;
        }
        FileOutputStream fos = new FileOutputStream(convFile);
        fos.write(multiFile.getBytes());
        fos.close();
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
