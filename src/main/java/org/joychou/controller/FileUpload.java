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
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
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
    private final Logger logger = LoggerFactory.getLogger(this.getClass());
    private static String randomFilePath = "";
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

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

        } catch (IOException e) {
            redirectAttributes.addFlashAttribute("message", "upload failed");
            logger.error("[-] Upload error: {}", e.getClass().getSimpleName());
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
        if (fileName == null) {
            logger.error("[-] Illegal file name");
            return "Upload failed. Illeagl picture.";
        }
        String Suffix = fileName.substring(fileName.lastIndexOf(".")); // 获取文件后缀名
        String mimeType = multifile.getContentType(); // 获取MIME类型
        String filePath = UPLOADED_FOLDER + fileName;
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
            logger.error("[-] Suffix error. Suffix is not allowed.");
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
                logger.error("[-] Mime type error. Mime type is not allowed.");
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
            logger.error("[-] Upload error: {}", e.getClass().getSimpleName());
            deleteFile(filePath);
            return "Upload failed";
        }

        logger.info("[+] Safe file. Successfully uploaded.");
        return String.format("You successfully uploaded '%s'", HtmlUtils.htmlEscape(filePath));
    }

    /**
     * Reduce an untrusted client-supplied file name to a bare file name (no directory components).
     * Returns null when the name is unusable.
     */
    private static String sanitizeFileName(String originalName) {
        if (originalName == null || originalName.indexOf('\0') >= 0) {
            return null;
        }
        String name = originalName.replace('\\', '/');
        name = name.substring(name.lastIndexOf('/') + 1);
        if (name.isEmpty() || ".".equals(name) || "..".equals(name)) {
            return null;
        }
        return name;
    }

    /**
     * Resolve an untrusted file name against the upload folder and make sure the
     * result stays inside it.
     */
    private static Path resolveUploadPath(String untrustedName) throws IOException {
        String name = sanitizeFileName(untrustedName);
        if (name == null) {
            throw new IOException("Illegal file name");
        }
        Path base = Paths.get(UPLOADED_FOLDER).toAbsolutePath().normalize();
        Path resolved = base.resolve(name).normalize();
        if (!resolved.startsWith(base) || resolved.equals(base)) {
            throw new IOException("Illegal file path");
        }
        return resolved;
    }

    private void deleteFile(String filePath) {
        try {
            Path delPath = Paths.get(filePath).toAbsolutePath().normalize();
            Path base = Paths.get(UPLOADED_FOLDER).toAbsolutePath().normalize();
            if (delPath.startsWith(base) && !delPath.equals(base) && Files.deleteIfExists(delPath)) {
                logger.info("[+] File deleted successfully!");
                return;
            }
        } catch (IOException | RuntimeException e) {
            logger.error("[-] File delete error: {}", e.getClass().getSimpleName());
        }
        logger.info("File delete failed!");
    }

    /**
     * Build an unpredictable file name from 16 bytes of cryptographically secure randomness (hex encoded).
     */
    private static String secureRandomName() {
        byte[] randomBytes = new byte[16];
        SECURE_RANDOM.nextBytes(randomBytes);
        StringBuilder sb = new StringBuilder(randomBytes.length * 2);
        for (byte b : randomBytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    /**
     * 为了使用ImageIO.read()
     *
     * 不建议使用transferTo，因为原始的MultipartFile会被覆盖
     * https://stackoverflow.com/questions/24339990/how-to-convert-a-multipart-file-to-file
     */
    private File convert(MultipartFile multiFile) throws Exception {
        String fileName = sanitizeFileName(multiFile.getOriginalFilename());
        if (fileName == null) {
            throw new IOException("Illegal file name");
        }
        String suffix = fileName.substring(fileName.lastIndexOf("."));
        // 随机生成一个同后缀名的文件 (name derived only from a CSPRNG value)
        Path convPath = resolveUploadPath(secureRandomName() + suffix);
        randomFilePath = convPath.toString();
        File convFile = convPath.toFile();
        boolean ret = convFile.createNewFile();
        if (!ret) {
            return null;
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
