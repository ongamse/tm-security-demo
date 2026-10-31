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
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import org.joychou.security.SecurityUtil;
import org.joychou.util.LogSanitizer;


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
            Path path = resolveInUploadDir(file.getOriginalFilename());
            Files.write(path, bytes);

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

        String fileName = baseName(multifile.getOriginalFilename());
        String Suffix = fileName.substring(fileName.lastIndexOf(".")); // 获取文件后缀名
        String mimeType = multifile.getContentType(); // 获取MIME类型
        String filePath = resolveInUploadDir(fileName).toString();
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
            logger.error("[-] Suffix error: {}", LogSanitizer.clean(Suffix));
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
                logger.error("[-] Mime type error: {}", LogSanitizer.clean(mimeType));
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
            Path path = resolveInUploadDir(fileName);
            Files.write(path, bytes);
        } catch (IOException e) {
            logger.error(e.toString());
            deleteFile(filePath);
            return "Upload failed";
        }

        logger.info("[+] Safe file. Suffix: {}, MIME: {}", LogSanitizer.clean(Suffix), LogSanitizer.clean(mimeType));
        logger.info("[+] Successfully uploaded {}", LogSanitizer.clean(filePath));
        return String.format("You successfully uploaded '%s'", HtmlUtils.htmlEscape(filePath));
    }

    /**
     * Reduce an untrusted file name to its last path segment (basename only).
     * Rejects empty names, dot segments and NUL bytes.
     */
    private static String baseName(String originalName) throws IOException {
        if (originalName == null || originalName.indexOf('\0') != -1) {
            throw new IOException("Illegal file name");
        }
        String normalized = originalName.replace('\\', '/');
        String name = normalized.substring(normalized.lastIndexOf('/') + 1);
        if (name.isEmpty() || name.equals(".") || name.equals("..")) {
            throw new IOException("Illegal file name");
        }
        return name;
    }

    /**
     * Resolve an untrusted file name against the fixed upload folder and make sure
     * the canonical result stays inside that folder.
     */
    private static Path resolveInUploadDir(String untrustedName) throws IOException {
        Path baseDir = Paths.get(UPLOADED_FOLDER).toAbsolutePath().normalize();
        Path resolved = baseDir.resolve(baseName(untrustedName)).normalize();
        if (!resolved.startsWith(baseDir) || resolved.equals(baseDir)) {
            throw new IOException("Illegal file path");
        }
        return resolved;
    }

    private void deleteFile(String filePath) {
        Path baseDir = Paths.get(UPLOADED_FOLDER).toAbsolutePath().normalize();
        Path target = Paths.get(filePath).toAbsolutePath().normalize();
        if (!target.startsWith(baseDir) || target.equals(baseDir)) {
            logger.info("Refuse to delete file outside upload folder");
            return;
        }
        // Atomic delete (no isFile()/exists() pre-check) to avoid a check-then-use race.
        try {
            if (Files.deleteIfExists(target)) {
                logger.info("[+] {} delete successfully!", LogSanitizer.clean(filePath));
                return;
            }
        } catch (IOException e) {
            logger.debug("Delete error: {}", LogSanitizer.clean(e.getClass().getSimpleName()));
        }
        logger.info("{} delete failed!", LogSanitizer.clean(filePath));
    }

    /**
     * 为了使用ImageIO.read()
     *
     * 不建议使用transferTo，因为原始的MultipartFile会被覆盖
     * https://stackoverflow.com/questions/24339990/how-to-convert-a-multipart-file-to-file
     */
    private File convert(MultipartFile multiFile) throws Exception {
        String fileName = baseName(multiFile.getOriginalFilename());
        String suffix = fileName.substring(fileName.lastIndexOf("."));
        // Validate the (basename-only) suffix resolves inside the upload folder.
        resolveInUploadDir("upload" + suffix);
        Path baseDir = Paths.get(UPLOADED_FOLDER).toAbsolutePath().normalize();
        // 随机生成一个同后缀名的文件: created atomically with an unpredictable
        // name (JDK SecureRandom) and owner-only permissions on POSIX systems.
        Path randomPath = Files.createTempFile(baseDir, "upload-", suffix);
        randomFilePath = randomPath.toString();
        Files.write(randomPath, multiFile.getBytes());
        return randomPath.toFile();
    }

    /**
     * Check if the file is a picture.
     */
    private static boolean isImage(File file) throws IOException {
        BufferedImage bi = ImageIO.read(file);
        return bi != null;
    }
}
