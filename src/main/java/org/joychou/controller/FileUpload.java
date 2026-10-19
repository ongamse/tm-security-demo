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
    private final Logger logger = LoggerFactory.getLogger(this.getClass());
    private static String randomFilePath = "";

    /**
     * Sanitize the original filename from a multipart upload by stripping any
     * directory components and rejecting path-traversal sequences.
     *
     * @return the bare filename, or null if invalid
     */
    private static String sanitizeFilename(String originalFilename) {
        if (originalFilename == null || originalFilename.isEmpty()) {
            return null;
        }
        // Strip directory components (handle both Unix and Windows separators)
        String sanitized = originalFilename;
        int lastSlash = sanitized.lastIndexOf('/');
        if (lastSlash >= 0) {
            sanitized = sanitized.substring(lastSlash + 1);
        }
        int lastBackslash = sanitized.lastIndexOf('\\');
        if (lastBackslash >= 0) {
            sanitized = sanitized.substring(lastBackslash + 1);
        }
        // Reject empty result or path-traversal sequences
        if (sanitized.isEmpty() || sanitized.contains("..")) {
            return null;
        }
        return sanitized;
    }

    /**
     * Resolve {@code filePath} to an absolute, normalized path and verify it
     * resides under {@link #UPLOADED_FOLDER}.  Throws {@link IOException} when
     * the resolved path escapes the allowed base directory.
     */
    private static Path validatePathUnderBase(String filePath) throws IOException {
        Path resolved = Paths.get(filePath).toAbsolutePath().normalize();
        Path base = Paths.get(UPLOADED_FOLDER).toAbsolutePath().normalize();
        if (!resolved.startsWith(base)) {
            throw new IOException("Path traversal detected: path is outside upload directory");
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
            // Sanitize filename to prevent path traversal
            String safeName = sanitizeFilename(file.getOriginalFilename());
            if (safeName == null) {
                redirectAttributes.addFlashAttribute("message", "Invalid file name");
                return "redirect:/file/status";
            }
            // Get the file and save it somewhere
            byte[] bytes = file.getBytes();
            Path path = validatePathUnderBase(UPLOADED_FOLDER + safeName);
            Files.write(path, bytes);

            redirectAttributes.addFlashAttribute("message",
                    "You successfully uploaded '" + UPLOADED_FOLDER + safeName + "'");

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
        String fileName = sanitizeFilename(rawFileName);
        if (fileName == null) {
            return "Upload failed. Invalid file name.";
        }
        String Suffix = fileName.substring(fileName.lastIndexOf(".")); // 获取文件后缀名
        String mimeType = multifile.getContentType(); // 获取MIME类型
        String filePath = UPLOADED_FOLDER + fileName;
        // Validate the constructed path stays within the upload directory
        try {
            validatePathUnderBase(filePath);
        } catch (IOException e) {
            return "Upload failed. Invalid file path.";
        }
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
            Path path = validatePathUnderBase(UPLOADED_FOLDER + fileName);
            Files.write(path, bytes);
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
        // Validate the path is within the upload directory before deletion
        try {
            validatePathUnderBase(filePath);
        } catch (IOException e) {
            logger.error("Refusing to delete file outside upload directory: " + filePath);
            return;
        }
        File delFile = new File(filePath);
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
        String rawFileName = multiFile.getOriginalFilename();
        String safeName = sanitizeFilename(rawFileName);
        if (safeName == null) {
            throw new IOException("Invalid file name");
        }
        String suffix = safeName.substring(safeName.lastIndexOf("."));
        UUID uuid = Generators.timeBasedGenerator().generate();
        randomFilePath = UPLOADED_FOLDER + uuid + suffix;
        // Validate the random path is still under the upload directory
        Path validatedPath = validatePathUnderBase(randomFilePath);
        // 随机生成一个同后缀名的文件
        File convFile = validatedPath.toFile();
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
        // Validate the file is within the upload directory
        Path filePath = file.toPath().toAbsolutePath().normalize();
        Path base = Paths.get(UPLOADED_FOLDER).toAbsolutePath().normalize();
        if (!filePath.startsWith(base)) {
            throw new IOException("Path traversal detected: file is outside upload directory");
        }
        BufferedImage bi = ImageIO.read(file);
        return bi != null;
    }
}
