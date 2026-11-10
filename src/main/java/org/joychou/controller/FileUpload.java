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
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.UUID;

import org.joychou.security.SecurityUtil;
import org.joychou.util.WebUtils;


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
            Path path = resolveUploadPath(file.getOriginalFilename());
            Files.write(path, bytes);

            redirectAttributes.addFlashAttribute("message",
                    "You successfully uploaded '" + path + "'");

        } catch (IllegalArgumentException e) {
            redirectAttributes.addFlashAttribute("message", "Illegal file name");
        } catch (IOException e) {
            redirectAttributes.addFlashAttribute("message", "upload failed");
            logger.error("Upload IO error, error type: {}", e.getClass().getSimpleName());
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

        String fileName;
        String filePath;
        try {
            // Strip any directory component and make sure the target stays inside UPLOADED_FOLDER
            Path safePath = resolveUploadPath(multifile.getOriginalFilename());
            fileName = safePath.getFileName().toString();
            filePath = safePath.toString();
        } catch (IllegalArgumentException e) {
            logger.error("[-] Illegal file name");
            return "Upload failed. Illeagl picture.";
        }
        String Suffix = fileName.substring(fileName.lastIndexOf(".")); // 获取文件后缀名
        String mimeType = multifile.getContentType(); // 获取MIME类型
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
            logger.error("[-] Suffix error, suffix length: {}", null == Suffix ? 0 : Suffix.length());
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
                logger.error("[-] Mime type error, mime type length: {}", null == mimeType ? 0 : mimeType.length());
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
            Path path = resolveUploadPath(fileName);
            Files.write(path, bytes);
        } catch (IOException e) {
            logger.error("Upload IO error, error type: {}", e.getClass().getSimpleName());
            deleteFile(filePath);
            return "Upload failed";
        }

        logger.info("[+] Safe file. Suffix length: {}, MIME length: {}", null == Suffix ? 0 : Suffix.length(), null == mimeType ? 0 : mimeType.length());
        logger.info("[+] Successfully uploaded file, path length: {}", null == filePath ? 0 : filePath.length());
        return String.format("You successfully uploaded '%s'", WebUtils.escapeHtml(filePath));
    }

    /**
     * Reduce an untrusted file name to a bare file name (no directory part).
     *
     * @throws IllegalArgumentException if the name is empty or not a plain file name
     */
    private static String sanitizeFileName(String originalName) {
        if (originalName == null || originalName.indexOf('\0') != -1) {
            throw new IllegalArgumentException("Illegal file name");
        }
        String name = originalName.replace('\\', '/');
        name = name.substring(name.lastIndexOf('/') + 1);
        if (name.isEmpty() || ".".equals(name) || "..".equals(name)) {
            throw new IllegalArgumentException("Illegal file name");
        }
        return name;
    }

    /**
     * Resolve an untrusted file name inside UPLOADED_FOLDER and verify it does not escape it.
     *
     * @throws IllegalArgumentException if the resulting path is outside UPLOADED_FOLDER
     */
    private static Path resolveUploadPath(String originalName) {
        Path base = Paths.get(UPLOADED_FOLDER).toAbsolutePath().normalize();
        Path resolved = base.resolve(sanitizeFileName(originalName)).normalize();
        if (!resolved.startsWith(base) || resolved.equals(base)) {
            throw new IllegalArgumentException("Illegal file path");
        }
        return resolved;
    }

    private void deleteFile(String filePath) {
        Path base = Paths.get(UPLOADED_FOLDER).toAbsolutePath().normalize();
        Path target = Paths.get(filePath).toAbsolutePath().normalize();
        if (!target.startsWith(base) || target.equals(base)) {
            logger.info("Refusing to delete path outside upload folder");
            return;
        }
        // Delete directly (no isFile/exists pre-check) and handle failure to avoid a TOCTOU gap.
        try {
            Files.delete(target);
            logger.info("[+] File delete successfully!");
            return;
        } catch (IOException e) {
            // fall through to the failure log below
        }
        logger.info("File delete failed!");
    }

    /**
     * 为了使用ImageIO.read()
     *
     * 不建议使用transferTo，因为原始的MultipartFile会被覆盖
     * https://stackoverflow.com/questions/24339990/how-to-convert-a-multipart-file-to-file
     */
    private File convert(MultipartFile multiFile) throws Exception {
        String fileName = sanitizeFileName(multiFile.getOriginalFilename());
        String suffix = fileName.substring(fileName.lastIndexOf("."));
        // UUID.randomUUID() is backed by SecureRandom (unpredictable, unlike a time-based UUID)
        UUID uuid = UUID.randomUUID();
        // 随机生成一个同后缀名的文件
        Path convPath = resolveUploadPath(uuid + suffix);
        randomFilePath = convPath.toString();
        File convFile = convPath.toFile();
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
