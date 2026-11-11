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
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
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
            Path path = resolveUploadPath(file.getOriginalFilename());
            if (path == null) {
                redirectAttributes.addFlashAttribute("message", "upload failed: illegal file name");
                return "redirect:/file/status";
            }
            byte[] bytes = file.getBytes();
            Files.write(path, bytes, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING,
                    StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS);

            redirectAttributes.addFlashAttribute("message",
                    "You successfully uploaded '" + path + "'");

        } catch (IOException e) {
            redirectAttributes.addFlashAttribute("message", "upload failed");
            logger.error("File upload exception: " + e.getClass().getSimpleName());
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
        if (safePath == null || fileName.lastIndexOf('.') < 0) {
            logger.error("[-] Illegal file name");
            return "Upload failed. Illeagl picture.";
        }
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
            logger.error("[-] Suffix error: not an allowed image suffix");
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
                logger.error("[-] Mime type error: blacklisted MIME type");
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
            Files.write(safePath, bytes, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING,
                    StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS);
        } catch (IOException e) {
            logger.error("File upload exception: " + e.getClass().getSimpleName());
            deleteFile(filePath);
            return "Upload failed";
        }

        logger.info("[+] Safe file passed all upload checks.");
        logger.info("[+] Successfully uploaded file.");
        return String.format("You successfully uploaded '%s'", HtmlUtils.htmlEscape(filePath));
    }

    /**
     * Strip any directory components (both / and \) from an uploaded file name.
     *
     * @return bare file name, or null if empty / contains NUL / is a dot segment
     */
    private static String sanitizeFileName(String originalName) {
        if (originalName == null || originalName.indexOf('\0') != -1) {
            return null;
        }
        String name = originalName.substring(
                Math.max(originalName.lastIndexOf('/'), originalName.lastIndexOf('\\')) + 1);
        if (name.isEmpty() || name.equals(".") || name.equals("..")) {
            return null;
        }
        return name;
    }

    /**
     * Resolve an uploaded file name inside UPLOADED_FOLDER; null if it would escape.
     */
    private static Path resolveUploadPath(String originalName) {
        String name = sanitizeFileName(originalName);
        return name == null ? null : SecurityUtil.resolveInBase(UPLOADED_FOLDER, name);
    }

    private void deleteFile(String filePath) {
        if (filePath == null || filePath.isEmpty()) {
            logger.info("File delete failed!");
            return;
        }
        try {
            if (Files.deleteIfExists(Paths.get(filePath))) {
                logger.info("[+] File deleted successfully!");
                return;
            }
        } catch (IOException | InvalidPathException e) {
            logger.info("File delete exception: " + e.getClass().getSimpleName());
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
        if (fileName == null || fileName.lastIndexOf('.') < 0) {
            return null;
        }
        String suffix = fileName.substring(fileName.lastIndexOf("."));
        UUID uuid = UUID.randomUUID();
        Path randomPath = resolveUploadPath(uuid + suffix);
        if (randomPath == null) {
            return null;
        }
        randomFilePath = randomPath.toString();
        // 随机生成一个同后缀名的文件
        // CREATE_NEW atomically fails if the file (or a symlink) already exists.
        try (OutputStream out = Files.newOutputStream(randomPath,
                StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)) {
            out.write(multiFile.getBytes());
        } catch (FileAlreadyExistsException e) {
            return null;
        }
        return randomPath.toFile();
    }

    /**
     * Check if the file is a picture.
     */
    private static boolean isImage(File file) throws IOException {
        try (InputStream in = Files.newInputStream(file.toPath(), LinkOption.NOFOLLOW_LINKS)) {
            BufferedImage bi = ImageIO.read(in);
            return bi != null;
        }
    }
}
