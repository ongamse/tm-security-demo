package org.joychou.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import org.springframework.web.util.HtmlUtils;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import org.joychou.security.LogSafe;
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
            Path path = resolveUploadPath(sanitizeFileName(file.getOriginalFilename()));
            if (path == null) {
                redirectAttributes.addFlashAttribute("message", "Illegal file name");
                return "redirect:/file/status";
            }
            byte[] bytes = file.getBytes();
            Files.write(path, bytes);

            redirectAttributes.addFlashAttribute("message",
                    "You successfully uploaded '" + path + "'");

        } catch (IOException e) {
            redirectAttributes.addFlashAttribute("message", "upload failed");
            logger.error("file operation failed: {}", LogSafe.errorName(e));
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

        String fileName = sanitizeFileName(multifile.getOriginalFilename());
        Path safePath = resolveUploadPath(fileName);
        if (safePath == null) {
            return "Upload failed. Illeagl picture.";
        }
        String Suffix = fileName.substring(fileName.lastIndexOf(".")); // 获取文件后缀名
        String mimeType = multifile.getContentType(); // 获取MIME类型
        String filePath = safePath.toString();
        File excelFile = convert(multifile, fileName);


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
            logger.error("[-] Suffix error: {}", LogSafe.fingerprint(Suffix));
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
                logger.error("[-] Mime type error: {}", LogSafe.fingerprint(mimeType));
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
            logger.error("file operation failed: {}", LogSafe.errorName(e));
            deleteFile(filePath);
            return "Upload failed";
        }

        logger.info("[+] Safe file. Suffix: {}, MIME: {}", LogSafe.fingerprint(Suffix), LogSafe.fingerprint(mimeType));
        logger.info("[+] Successfully uploaded {}", LogSafe.fingerprint(filePath));
        return String.format("You successfully uploaded '%s'", HtmlUtils.htmlEscape(filePath));
    }

    /**
     * Reduce a client-supplied file name to a bare file name (no directory components).
     *
     * @return the bare file name, or null if it is not acceptable
     */
    private static String sanitizeFileName(String originalName) {
        if (originalName == null) {
            return null;
        }
        int idx = Math.max(originalName.lastIndexOf('/'), originalName.lastIndexOf('\\'));
        String name = originalName.substring(idx + 1);
        if (name.isEmpty() || name.equals(".") || name.equals("..") || name.indexOf('\0') != -1) {
            return null;
        }
        return name;
    }

    /**
     * Resolve a bare file name under UPLOADED_FOLDER and make sure the result does not escape it.
     *
     * @return the safe absolute path, or null if the name is null / escapes the upload folder
     */
    private static Path resolveUploadPath(String fileName) {
        if (fileName == null) {
            return null;
        }
        try {
            Path base = Paths.get(UPLOADED_FOLDER).toAbsolutePath().normalize();
            Path resolved = base.resolve(fileName).normalize();
            if (!resolved.startsWith(base) || resolved.equals(base)) {
                return null;
            }
            return resolved;
        } catch (java.nio.file.InvalidPathException e) {
            return null;
        }
    }

    private void deleteFile(String filePath) {
        Path safeDelPath = resolveUploadPath(sanitizeFileName(filePath));
        if (safeDelPath == null) {
            logger.info("Refusing to delete path outside upload folder");
            return;
        }
        try {
            // Delete directly (no separate exists()/isFile() check) to avoid a check-then-use race.
            if (Files.deleteIfExists(safeDelPath)) {
                logger.info("[+] {} delete successfully!", LogSafe.fingerprint(filePath));
                return;
            }
        } catch (IOException e) {
            logger.info("file operation failed: {}", LogSafe.errorName(e));
        }
        logger.info("{} delete failed!", LogSafe.fingerprint(filePath));
    }

    /**
     * 为了使用ImageIO.read()
     *
     * 不建议使用transferTo，因为原始的MultipartFile会被覆盖
     * https://stackoverflow.com/questions/24339990/how-to-convert-a-multipart-file-to-file
     */
    private File convert(MultipartFile multiFile, String fileName) throws Exception {
        String suffix = fileName.substring(fileName.lastIndexOf("."));
        // 随机生成一个同后缀名的文件: unpredictable name from the JDK's SecureRandom-backed
        // Files.createTempFile, created atomically inside the controlled upload folder
        Path base = Paths.get(UPLOADED_FOLDER).toAbsolutePath().normalize();
        Path convPath;
        try {
            convPath = Files.createTempFile(base, "upload-", suffix);
        } catch (IOException | IllegalArgumentException e) {
            logger.error("file operation failed: {}", LogSafe.errorName(e));
            return null;
        }
        if (!convPath.normalize().startsWith(base)) {
            Files.deleteIfExists(convPath);
            return null;
        }
        randomFilePath = convPath.toString();
        File convFile = convPath.toFile();
        Files.write(convPath, multiFile.getBytes());
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
