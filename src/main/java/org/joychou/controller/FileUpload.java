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
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.SecureRandom;
import java.util.regex.Pattern;

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
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private static final Pattern SAFE_SUFFIX = Pattern.compile("\\.[A-Za-z0-9]{1,10}");

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

        Path safePath;
        try {
            safePath = resolveUploadPath(multifile.getOriginalFilename());
        } catch (IOException e) {
            logger.error("[-] Illegal file name");
            return "Upload failed. Illeagl picture.";
        }
        String fileName = safePath.getFileName().toString();
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
        deleteFile(excelFile.getPath());

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
        return HtmlUtils.htmlEscape(String.format("You successfully uploaded '%s'", filePath));
    }

    /**
     * Build a path inside UPLOADED_FOLDER from a client supplied file name.
     * Only the last path segment of the name is used, and the resulting path
     * must stay inside UPLOADED_FOLDER.
     */
    private static Path resolveUploadPath(String originalName) throws IOException {
        if (originalName == null || originalName.indexOf('\0') >= 0) {
            throw new IOException("Illegal file name");
        }
        String name = originalName.replace('\\', '/');
        name = name.substring(name.lastIndexOf('/') + 1);
        if (name.isEmpty() || name.equals(".") || name.equals("..")) {
            throw new IOException("Illegal file name");
        }
        Path root = Paths.get(UPLOADED_FOLDER).toAbsolutePath().normalize();
        Path resolved = root.resolve(name).normalize();
        if (!resolved.startsWith(root) || !root.equals(resolved.getParent())) {
            throw new IOException("Illegal file path");
        }
        return resolved;
    }

    private static boolean isInUploadFolder(String filePath) {
        if (filePath == null || filePath.isEmpty() || filePath.indexOf('\0') >= 0) {
            return false;
        }
        Path root = Paths.get(UPLOADED_FOLDER).toAbsolutePath().normalize();
        return Paths.get(filePath).toAbsolutePath().normalize().startsWith(root);
    }

    private void deleteFile(String filePath) {
        if (!isInUploadFolder(filePath)) {
            logger.info("Refuse to delete file outside upload folder");
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
        String fileName = resolveUploadPath(multiFile.getOriginalFilename()).getFileName().toString();
        String suffix = fileName.substring(fileName.lastIndexOf("."));
        // Only keep a short alphanumeric extension; otherwise store without one.
        if (!SAFE_SUFFIX.matcher(suffix).matches()) {
            suffix = "";
        }
        // 随机生成一个同后缀名的文件 (unpredictable name from SecureRandom)
        byte[] rnd = new byte[16];
        SECURE_RANDOM.nextBytes(rnd);
        StringBuilder hex = new StringBuilder(32);
        for (byte b : rnd) {
            hex.append(String.format("%02x", b));
        }
        Path root = Paths.get(UPLOADED_FOLDER).toAbsolutePath().normalize();
        Path convPath = root.resolve(hex + suffix).normalize();
        if (!root.equals(convPath.getParent())) {
            throw new IOException("Illegal file path");
        }
        // Atomic create (fails if the file already exists), owner-only where supported.
        if (FileSystems.getDefault().supportedFileAttributeViews().contains("posix")) {
            Files.createFile(convPath, PosixFilePermissions.asFileAttribute(
                    PosixFilePermissions.fromString("rw-------")));
        } else {
            Files.createFile(convPath);
        }
        Files.write(convPath, multiFile.getBytes());
        return convPath.toFile();
    }

    /**
     * Check if the file is a picture.
     */
    private static boolean isImage(File file) throws IOException {
        if (file == null || !isInUploadFolder(file.getPath())) {
            return false;
        }
        BufferedImage bi = ImageIO.read(file);
        return bi != null;
    }
}
